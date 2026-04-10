package proxy

import (
	"log/slog"
	"net/http"
	"sort"
	"strings"

	"github.com/karloie/multipass/internal/auth"
	"github.com/karloie/multipass/internal/authz"
	"github.com/karloie/multipass/internal/config"
)

const (
	backendTypePrometheus = "prometheus"
	backendTypeJWT        = "jwt"
	backendTypeWeb        = "web"
	backendTypeGeneric    = "generic"

	headerXScopeOrgID = "X-Scope-OrgID"

	// Segments for access control
	segmentDev   = "dev"
	segmentOps   = "ops"
	segmentAdmin = "admin"
)

// injectBackendHeaders adds backend headers.
func (p *Proxy) injectBackendHeaders(req *http.Request, backendConfig config.BackendConfig, backendName string) {
	for key, value := range backendConfig.Headers {
		req.Header.Set(key, value)
	}

	switch backendConfig.Type {
	case backendTypePrometheus:
		p.injectPrometheusHeaders(req)
	case backendTypeJWT:
		p.injectJWTHeaders(req)
	case backendTypeWeb:
		req.Header.Del(headerAuthorization)
		p.injectWebHeaders(req, backendConfig.WebConfig)
	case backendTypeGeneric:
	default:
		slog.Warn("unknown backend type; treating as generic",
			slog.String("backend_type", backendConfig.Type),
			slog.String("backend", backendName),
		)
	}
}

// injectPrometheusHeaders adds the scope header.
func (p *Proxy) injectPrometheusHeaders(req *http.Request) {
	if namespace, ok := req.Context().Value(namespaceKey).(string); ok && namespace != "" {
		req.Header.Set(headerXScopeOrgID, namespace)
	}
}

// injectJWTHeaders adds the bearer token header.
func (p *Proxy) injectJWTHeaders(req *http.Request) {
	if jwt, ok := req.Context().Value(jwtTokenKey).(string); ok && jwt != "" {
		req.Header.Set(headerAuthorization, headerBearerPrefix+jwt)
	}
}

// injectWebHeaders adds user identity headers.
func (p *Proxy) injectWebHeaders(req *http.Request, webConfig *config.WebConfig) {
	if webConfig == nil {
		return
	}

	userInfo, ok := req.Context().Value(userInfoKey).(*auth.UserInfo)
	if !ok || userInfo == nil {
		return
	}

	if webConfig.UserHeader != "" {
		if webUser := resolveWebUser(userInfo); webUser != "" {
			req.Header.Set(webConfig.UserHeader, webUser)
		}
	}
	if webConfig.EmailHeader != "" && userInfo.Email != "" {
		req.Header.Set(webConfig.EmailHeader, userInfo.Email)
	}
	if webConfig.NameHeader != "" && userInfo.Name != "" {
		req.Header.Set(webConfig.NameHeader, userInfo.Name)
	}

	groups := resolveWebGroups(req, userInfo)

	if webConfig.GroupsHeader != "" && len(groups) > 0 {
		req.Header.Set(webConfig.GroupsHeader, strings.Join(groups, ","))
	}

	if webConfig.RoleHeader != "" {
		if role := resolveMappedRole(resolveWebRoleInputs(req, userInfo), webConfig.RoleMappings); role != "" {
			req.Header.Set(webConfig.RoleHeader, role)
		}
	}
}

func resolveWebUser(userInfo *auth.UserInfo) string {
	if userInfo == nil {
		return ""
	}
	if strings.TrimSpace(userInfo.Username) != "" {
		return strings.TrimSpace(userInfo.Username)
	}
	return strings.TrimSpace(userInfo.ID)
}

// resolveSegment determines the user's segment (dev, ops, admin) based on internal and elevated roles.
// Priority: admin > ops > dev (defaults to dev if no recognized roles).
func resolveSegment(req *http.Request) string {
	perms, ok := req.Context().Value(permissionsKey).(*authz.Permission)
	if !ok || perms == nil {
		return segmentDev
	}

	// Combine internal roles and elevated roles
	allRoles := make([]string, 0, len(perms.InternalRoles)+len(perms.ElevatedRoles))
	allRoles = append(allRoles, perms.InternalRoles...)
	for _, elevated := range perms.ElevatedRoles {
		allRoles = append(allRoles, elevated.Role)
	}

	// Check for admin first (highest priority)
	for _, role := range allRoles {
		normalized := strings.ToLower(strings.TrimSpace(role))
		if normalized == "admin" || normalized == "plat-admin" {
			return segmentAdmin
		}
	}

	// Check for ops roles
	for _, role := range allRoles {
		normalized := strings.ToLower(strings.TrimSpace(role))
		if normalized == "ops" || normalized == "plat-ops" || normalized == "devops" {
			return segmentOps
		}
	}

	// Default to dev segment
	return segmentDev
}

func resolveWebGroups(req *http.Request, userInfo *auth.UserInfo) []string {
	perms, ok := req.Context().Value(permissionsKey).(*authz.Permission)
	if ok && perms != nil && len(perms.ExternalGroups) > 0 {
		return perms.ExternalGroups
	}
	if userInfo != nil && len(userInfo.Groups) > 0 {
		return userInfo.Groups
	}
	return nil
}

func resolveWebRoleInputs(req *http.Request, userInfo *auth.UserInfo) []string {
	groups := resolveWebGroups(req, userInfo)

	perms, ok := req.Context().Value(permissionsKey).(*authz.Permission)
	if !ok || perms == nil || len(perms.InternalRoles) == 0 {
		return groups
	}

	inputs := make([]string, 0, len(perms.InternalRoles)+len(groups))
	seen := make(map[string]struct{}, len(perms.InternalRoles)+len(groups))

	for _, role := range perms.InternalRoles {
		trimmed := strings.TrimSpace(role)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		inputs = append(inputs, trimmed)
	}

	for _, group := range groups {
		trimmed := strings.TrimSpace(group)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		inputs = append(inputs, trimmed)
	}

	return inputs
}

func resolveMappedRole(groups []string, roleMappings map[string]string) string {
	if len(groups) == 0 || len(roleMappings) == 0 {
		return ""
	}

	matchedRoles := make([]string, 0, len(groups))
	for _, group := range groups {
		role := strings.TrimSpace(roleMappings[group])
		if role == "" {
			continue
		}
		matchedRoles = append(matchedRoles, role)
	}
	if len(matchedRoles) == 0 {
		return ""
	}

	sort.SliceStable(matchedRoles, func(i, j int) bool {
		return rolePriority(matchedRoles[i]) > rolePriority(matchedRoles[j])
	})

	return matchedRoles[0]
}

func rolePriority(role string) int {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "grafanaadmin":
		return 400
	case "admin":
		return 300
	case "editor":
		return 200
	case "viewer":
		return 100
	default:
		return 0
	}
}
