// Package config loads and validates Multipass YAML configuration.
package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/karloie/multipass/internal/auth"
	queryrewrite "github.com/karloie/multipass/internal/query"
	"gopkg.in/yaml.v3"
)

const (
	DefaultOIDCLoginPath    = "/login"
	DefaultOIDCCallbackPath = "/login/generic_oauth"
	DefaultOIDCLogoutPath   = "/logout"
)

// Config defines the Multipass gateway configuration.
type Config struct {
	Server   ServerConfig             `yaml:"server"`
	Auth     AuthConfig               `yaml:"auth"`
	Authz    AuthzConfig              `yaml:"authz"`
	PIM      PIMConfig                `yaml:"pim,omitempty"`
	Audit    AuditConfig              `yaml:"audit"`
	Backends map[string]BackendConfig `yaml:"backends"`
}

// ServerConfig defines server settings.
type ServerConfig struct {
	Port                int  `yaml:"port"`
	TrustForwardedProto bool `yaml:"trustForwardedProto,omitempty"`
}

// AuthConfig defines authentication settings.
type AuthConfig struct {
	Provider     string             `yaml:"provider"` // "oidc"
	OIDC         OIDCConfig         `yaml:"oidc"`
	SessionTTL   string             `yaml:"sessionTTL"` // e.g., "24h"
	SessionStore SessionStoreConfig `yaml:"sessionStore,omitempty"`
	TrustedProxy TrustedProxyConfig `yaml:"trustedProxy,omitempty"`
}

// TrustedProxyConfig defines trusted upstream header auth.
type TrustedProxyConfig struct {
	Enabled           bool   `yaml:"enabled,omitempty"`
	UserHeader        string `yaml:"userHeader,omitempty"`
	IDHeader          string `yaml:"idHeader,omitempty"`
	EmailHeader       string `yaml:"emailHeader,omitempty"`
	NameHeader        string `yaml:"nameHeader,omitempty"`
	GroupsHeader      string `yaml:"groupsHeader,omitempty"`
	CallerHeader      string `yaml:"callerHeader,omitempty"`
	CallerValue       string `yaml:"callerValue,omitempty"`
	PrincipalIDHeader string `yaml:"principalIdHeader,omitempty"`
	TenantIDHeader    string `yaml:"tenantIdHeader,omitempty"`
	SecretHeader      string `yaml:"secretHeader,omitempty"`
	SecretValue       string `yaml:"secretValue,omitempty"`
}

// SessionStoreConfig defines browser session storage.
type SessionStoreConfig struct {
	Store string `yaml:"store"` // "memory"
}

// OIDCConfig defines OIDC provider settings.
type OIDCConfig struct {
	ProviderName          string   `yaml:"providerName"` // e.g., "forgerock", "keycloak"
	IssuerURL             string   `yaml:"issuerUrl"`
	ClientID              string   `yaml:"clientId"`
	ClientSecret          string   `yaml:"clientSecret"`
	RedirectURL           string   `yaml:"redirectUrl"`
	PostLogoutRedirectURL string   `yaml:"postLogoutRedirectUrl,omitempty"`
	LoginPath             string   `yaml:"loginPath,omitempty"`
	CallbackPath          string   `yaml:"callbackPath,omitempty"`
	LogoutPath            string   `yaml:"logoutPath,omitempty"`
	Scopes                []string `yaml:"scopes"`
}

type OIDCPaths struct {
	LoginPath    string
	CallbackPath string
	LogoutPath   string
}

func (c OIDCConfig) Paths() OIDCPaths {
	paths := OIDCPaths{
		LoginPath:    DefaultOIDCLoginPath,
		CallbackPath: DefaultOIDCCallbackPath,
		LogoutPath:   DefaultOIDCLogoutPath,
	}

	if c.LoginPath != "" {
		paths.LoginPath = c.LoginPath
	}
	if c.CallbackPath != "" {
		paths.CallbackPath = c.CallbackPath
	}
	if c.LogoutPath != "" {
		paths.LogoutPath = c.LogoutPath
	}

	return paths
}

func (c OIDCConfig) EffectivePostLogoutRedirectURL() string {
	if c.PostLogoutRedirectURL != "" {
		return c.PostLogoutRedirectURL
	}

	if c.RedirectURL == "" {
		return ""
	}

	parsed, err := url.Parse(c.RedirectURL)
	if err != nil || !parsed.IsAbs() {
		return ""
	}

	parsed.Path = c.Paths().LoginPath
	parsed.RawQuery = ""
	parsed.Fragment = ""

	return parsed.String()
}

// AuthzConfig defines authorization settings.
type AuthzConfig struct {
	Enabled             bool                      `yaml:"enabled"`       // Enable authorization
	Provider            string                    `yaml:"provider"`      // "token"
	GroupMappings       map[string][]string       `yaml:"groupMappings"` // group -> namespaces
	RoleMappings        map[string][]string       `yaml:"roleMappings,omitempty"`
	TeamAccess          TeamAccessConfig          `yaml:"teamAccess,omitempty"`
	LocalCluster        string                    `yaml:"localCluster,omitempty"`
	ClusterResolver     ClusterResolverConfig     `yaml:"clusterResolver,omitempty"`
	NamespaceClassifier NamespaceClassifierConfig `yaml:"namespaceClassifier,omitempty"`
}

// TeamAccessConfig defines optional team-based request authorization.
type TeamAccessConfig struct {
	Enabled        bool              `yaml:"enabled,omitempty"`
	RequestParam   string            `yaml:"requestParam,omitempty"`
	RequestHeader  string            `yaml:"requestHeader,omitempty"`
	GroupToTeamID  map[string]string `yaml:"groupToTeamId,omitempty"`
	AdminRoles     []string          `yaml:"adminRoles,omitempty"`
	DevopsRoles    []string          `yaml:"devopsRoles,omitempty"`
	DeveloperRoles []string          `yaml:"developerRoles,omitempty"`
	MappingVersion string            `yaml:"mappingVersion,omitempty"`
}

// PIMConfig defines temporary elevated role request settings.
type PIMConfig struct {
	Enabled           bool                     `yaml:"enabled,omitempty"`
	AllowSelfApproval bool                     `yaml:"allowSelfApproval,omitempty"`
	DefaultDuration   string                   `yaml:"defaultDuration,omitempty"`
	Roles             map[string]PIMRoleConfig `yaml:"roles,omitempty"`
}

// PIMRoleConfig defines one requestable temporary role.
type PIMRoleConfig struct {
	Approver       string   `yaml:"approver,omitempty"`
	ApproverGroups []string `yaml:"approverGroups,omitempty"`
	MaxDuration    string   `yaml:"maxDuration,omitempty"`
}

// ClusterResolverConfig maps authenticated callers to cluster names.
type ClusterResolverConfig struct {
	Source   string            `yaml:"source,omitempty"`
	Mappings map[string]string `yaml:"mappings,omitempty"`
}

// NamespaceClassifierConfig maps raw namespaces to Multipass scopes.
type NamespaceClassifierConfig struct {
	DefaultSegment   string                                 `yaml:"defaultSegment,omitempty"`
	OpsExact         []string                               `yaml:"opsExact,omitempty"`
	OpsPrefixes      []string                               `yaml:"opsPrefixes,omitempty"`
	OpsSuffixes      []string                               `yaml:"opsSuffixes,omitempty"`
	ClusterOverrides map[string]NamespaceClassifierOverride `yaml:"clusterOverrides,omitempty"`
}

// NamespaceClassifierOverride adds cluster-specific rules.
type NamespaceClassifierOverride struct {
	DefaultSegment string   `yaml:"defaultSegment,omitempty"`
	OpsExact       []string `yaml:"opsExact,omitempty"`
	OpsPrefixes    []string `yaml:"opsPrefixes,omitempty"`
	OpsSuffixes    []string `yaml:"opsSuffixes,omitempty"`
}

// AuditConfig defines audit logging settings.
type AuditConfig struct {
	Enabled bool   `yaml:"enabled"` // Enable audit logging
	Store   string `yaml:"store"`   // "memory"
}

// BackendConfig defines a backend.
type BackendConfig struct {
	Type                 string                  `yaml:"type"` // prometheus, jwt, web, generic
	Endpoint             string                  `yaml:"endpoint"`
	Namespace            string                  `yaml:"namespace,omitempty"`
	NamespaceRouting     *NamespaceRoutingConfig `yaml:"namespaceRouting,omitempty"`
	QueryRewrite         *QueryRewriteConfig     `yaml:"queryRewrite,omitempty"`
	ReadinessURL         string                  `yaml:"readinessUrl,omitempty"`
	ExternalHost         string                  `yaml:"externalHost,omitempty"`
	ExternalPathPrefixes []string                `yaml:"externalPathPrefixes,omitempty"`
	Headers              map[string]string       `yaml:"headers,omitempty"`
	WebConfig            *WebConfig              `yaml:"webConfig,omitempty"` // Web-specific configuration
}

// NamespaceRoutingConfig defines namespace routing.
type NamespaceRoutingConfig struct {
	Mode      string `yaml:"mode,omitempty"`      // fixed, request
	Parameter string `yaml:"parameter,omitempty"` // request query parameter when mode=request
	Source    string `yaml:"source,omitempty"`    // query, body, both
}

// QueryRewriteConfig defines backend query-string mutations.
type QueryRewriteConfig = queryrewrite.RewriteConfig

// QueryRewriteOperation defines a single query-string mutation.
type QueryRewriteOperation = queryrewrite.RewriteOperation

// WebConfig defines web header injection.
type WebConfig struct {
	UserHeader   string            `yaml:"userHeader"`             // Header for user ID (e.g., X-WEBAUTH-USER)
	EmailHeader  string            `yaml:"emailHeader"`            // Header for user email (e.g., X-WEBAUTH-EMAIL)
	NameHeader   string            `yaml:"nameHeader"`             // Header for user name (e.g., X-WEBAUTH-NAME)
	GroupsHeader string            `yaml:"groupsHeader"`           // Header for original external groups from the JWT
	RoleHeader   string            `yaml:"roleHeader,omitempty"`   // Header for backend-native role (e.g., X-WEBAUTH-ROLE)
	RoleMappings map[string]string `yaml:"roleMappings,omitempty"` // Internal role -> backend-native role
}

func (c ClusterResolverConfig) HasMappings() bool {
	return len(c.Mappings) > 0
}

func (c ClusterResolverConfig) ResolveCluster(userInfo *auth.UserInfo) string {
	if userInfo == nil || len(c.Mappings) == 0 {
		return ""
	}

	switch strings.ToLower(strings.TrimSpace(c.Source)) {
	case "", "user":
		for _, candidate := range []string{userInfo.ID, userInfo.Username, userInfo.PrincipalID, userInfo.Email} {
			key := strings.TrimSpace(candidate)
			if key == "" {
				continue
			}
			if cluster, ok := c.Mappings[key]; ok {
				return strings.TrimSpace(cluster)
			}
		}
	}

	return ""
}

func (c NamespaceClassifierConfig) HasRules() bool {
	return strings.TrimSpace(c.DefaultSegment) != "" ||
		len(c.OpsExact) > 0 ||
		len(c.OpsPrefixes) > 0 ||
		len(c.OpsSuffixes) > 0 ||
		len(c.ClusterOverrides) > 0
}

func (c NamespaceClassifierConfig) Classify(cluster, namespace string) string {
	normalizedCluster := strings.TrimSpace(cluster)
	normalizedNamespace := normalizeNamespaceToken(namespace)
	if normalizedNamespace == "" {
		return strings.TrimSpace(namespace)
	}

	defaultSegment := strings.TrimSpace(c.DefaultSegment)
	if defaultSegment == "" {
		defaultSegment = "dev"
	}

	opsExact := normalizeNamespaceList(c.OpsExact)
	opsPrefixes := normalizeNamespaceList(c.OpsPrefixes)
	opsSuffixes := normalizeNamespaceList(c.OpsSuffixes)

	if override, ok := c.ClusterOverrides[normalizedCluster]; ok {
		if strings.TrimSpace(override.DefaultSegment) != "" {
			defaultSegment = strings.TrimSpace(override.DefaultSegment)
		}
		opsExact = append(opsExact, normalizeNamespaceList(override.OpsExact)...)
		opsPrefixes = append(opsPrefixes, normalizeNamespaceList(override.OpsPrefixes)...)
		opsSuffixes = append(opsSuffixes, normalizeNamespaceList(override.OpsSuffixes)...)
	}

	segment := defaultSegment
	if matchesNamespaceClassifier(normalizedNamespace, opsExact, opsPrefixes, opsSuffixes) {
		segment = "ops"
	}

	if normalizedCluster == "" {
		return segment
	}
	return normalizedCluster + "." + segment
}

func matchesNamespaceClassifier(namespace string, opsExact, opsPrefixes, opsSuffixes []string) bool {
	for _, exact := range opsExact {
		if namespace == exact {
			return true
		}
	}
	for _, prefix := range opsPrefixes {
		if strings.HasPrefix(namespace, prefix) {
			return true
		}
	}
	for _, suffix := range opsSuffixes {
		if strings.HasSuffix(namespace, suffix) {
			return true
		}
	}
	return false
}

func normalizeNamespaceList(values []string) []string {
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := normalizeNamespaceToken(value)
		if trimmed != "" {
			normalized = append(normalized, trimmed)
		}
	}
	return normalized
}

func normalizeNamespaceToken(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

// Load reads configuration from a YAML file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	data = []byte(os.ExpandEnv(string(data)))

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	if cfg.Server.Port == 0 {
		cfg.Server.Port = 8080
	}

	return &cfg, nil
}

// GetBackendNames returns backend names.
func (c *Config) GetBackendNames() []string {
	names := make([]string, 0, len(c.Backends))
	for name := range c.Backends {
		names = append(names, name)
	}
	return names
}

// Validate checks whether the configuration is valid.
func (c *Config) Validate() error {
	if err := c.validateServer(); err != nil {
		return err
	}
	if err := c.validateAuth(); err != nil {
		return err
	}
	if err := c.validateAuthz(); err != nil {
		return err
	}
	if err := c.validatePIM(); err != nil {
		return err
	}
	if err := c.validateAudit(); err != nil {
		return err
	}
	if err := c.validateBackends(); err != nil {
		return err
	}

	return nil
}

func (c *Config) validateServer() error {
	if c.Server.Port <= 0 || c.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d (must be 1-65535)", c.Server.Port)
	}

	return nil
}

func (c *Config) validateAuth() error {
	if c.Auth.Provider == "" {
		return fmt.Errorf("auth provider is required")
	}
	if c.Auth.Provider != "oidc" {
		return fmt.Errorf("auth provider must be: oidc")
	}

	if err := c.validateOIDC(); err != nil {
		return err
	}

	if c.Auth.SessionStore.Store != "" && c.Auth.SessionStore.Store != "memory" {
		return fmt.Errorf("auth sessionStore store must be 'memory' when configured")
	}

	if err := c.validateTrustedProxy(); err != nil {
		return err
	}

	return nil
}

func (c *Config) validateOIDC() error {
	if c.Auth.Provider != "oidc" {
		return nil
	}

	if c.Auth.OIDC.IssuerURL == "" {
		return fmt.Errorf("oidc issuerUrl is required")
	}
	if c.Auth.OIDC.ClientID == "" {
		return fmt.Errorf("oidc clientId is required")
	}
	if c.Auth.OIDC.ClientSecret == "" {
		return fmt.Errorf("oidc clientSecret is required")
	}
	if c.Auth.OIDC.RedirectURL == "" {
		return fmt.Errorf("oidc redirectUrl is required")
	}

	for fieldName, fieldValue := range map[string]string{
		"loginPath":    c.Auth.OIDC.LoginPath,
		"callbackPath": c.Auth.OIDC.CallbackPath,
		"logoutPath":   c.Auth.OIDC.LogoutPath,
	} {
		if fieldValue != "" && !strings.HasPrefix(fieldValue, "/") {
			return fmt.Errorf("oidc %s must start with '/'", fieldName)
		}
	}

	if c.Auth.OIDC.PostLogoutRedirectURL != "" {
		logoutURL, err := url.Parse(c.Auth.OIDC.PostLogoutRedirectURL)
		if err != nil || !logoutURL.IsAbs() {
			return fmt.Errorf("oidc postLogoutRedirectUrl must be an absolute URL")
		}
	}

	return nil
}

func (c *Config) validateTrustedProxy() error {
	if !c.Auth.TrustedProxy.Enabled {
		return nil
	}

	if c.Auth.TrustedProxy.UserHeader == "" && c.Auth.TrustedProxy.IDHeader == "" {
		return fmt.Errorf("auth trustedProxy requires userHeader or idHeader when enabled")
	}
	if c.Auth.TrustedProxy.SecretHeader == "" {
		return fmt.Errorf("auth trustedProxy secretHeader is required when enabled")
	}
	if c.Auth.TrustedProxy.SecretValue == "" {
		return fmt.Errorf("auth trustedProxy secretValue is required when enabled")
	}
	if (strings.TrimSpace(c.Auth.TrustedProxy.CallerHeader) == "") != (strings.TrimSpace(c.Auth.TrustedProxy.CallerValue) == "") {
		return fmt.Errorf("auth trustedProxy callerHeader and callerValue must be configured together")
	}

	return nil
}

func (c *Config) validateAuthz() error {
	if c.Authz.Enabled && c.Authz.Provider == "" {
		return fmt.Errorf("authz provider is required when authorization is enabled")
	}
	if c.Authz.Enabled {
		switch c.Authz.Provider {
		case "token":
		default:
			return fmt.Errorf("authz provider must be: token")
		}
	}

	if err := c.validateClusterResolver(); err != nil {
		return err
	}
	if err := c.validateRoleMappings(); err != nil {
		return err
	}

	return nil
}

func (c *Config) validateRoleMappings() error {
	if len(c.Authz.RoleMappings) == 0 {
		return nil
	}

	for externalRole, internalRoles := range c.Authz.RoleMappings {
		trimmedExternalRole := strings.TrimSpace(externalRole)
		if trimmedExternalRole == "" {
			return fmt.Errorf("authz roleMappings cannot contain empty external role names")
		}
		if len(internalRoles) == 0 {
			return fmt.Errorf("authz roleMappings for '%s' must contain at least one internal role", trimmedExternalRole)
		}
		for _, internalRole := range internalRoles {
			trimmedInternalRole := strings.TrimSpace(internalRole)
			if trimmedInternalRole == "" {
				return fmt.Errorf("authz roleMappings for '%s' cannot contain empty internal roles", trimmedExternalRole)
			}
			if _, ok := c.Authz.GroupMappings[trimmedInternalRole]; !ok {
				return fmt.Errorf("authz roleMappings for '%s' references unknown internal role '%s'", trimmedExternalRole, trimmedInternalRole)
			}
		}
	}

	return nil
}

func (c *Config) validatePIM() error {
	if !c.PIM.Enabled {
		return nil
	}

	if !c.Authz.Enabled {
		return fmt.Errorf("pim requires authz to be enabled")
	}

	if len(c.PIM.Roles) == 0 {
		return fmt.Errorf("pim roles are required when pim is enabled")
	}

	if strings.TrimSpace(c.PIM.DefaultDuration) != "" {
		duration, err := time.ParseDuration(strings.TrimSpace(c.PIM.DefaultDuration))
		if err != nil || duration <= 0 {
			return fmt.Errorf("pim defaultDuration must be a positive duration")
		}
	}

	for role, roleConfig := range c.PIM.Roles {
		trimmedRole := strings.TrimSpace(role)
		if trimmedRole == "" {
			return fmt.Errorf("pim roles cannot contain empty names")
		}
		if strings.TrimSpace(roleConfig.Approver) == "" && len(roleConfig.ApproverGroups) == 0 {
			return fmt.Errorf("pim role '%s' requires approver or approverGroups", trimmedRole)
		}
		for _, approverGroup := range roleConfig.ApproverGroups {
			if strings.TrimSpace(approverGroup) == "" {
				return fmt.Errorf("pim role '%s' approverGroups cannot contain empty values", trimmedRole)
			}
		}
		if strings.TrimSpace(roleConfig.MaxDuration) != "" {
			duration, err := time.ParseDuration(strings.TrimSpace(roleConfig.MaxDuration))
			if err != nil || duration <= 0 {
				return fmt.Errorf("pim role '%s' maxDuration must be a positive duration", trimmedRole)
			}
		}
		if _, ok := c.Authz.GroupMappings[trimmedRole]; !ok {
			return fmt.Errorf("pim role '%s' must exist in authz groupMappings", trimmedRole)
		}
	}

	return nil
}

func (c *Config) validateClusterResolver() error {
	resolver := c.Authz.ClusterResolver
	if !resolver.HasMappings() && strings.TrimSpace(resolver.Source) == "" {
		return nil
	}

	if !resolver.HasMappings() {
		return fmt.Errorf("authz clusterResolver mappings are required when clusterResolver is configured")
	}

	switch strings.ToLower(strings.TrimSpace(resolver.Source)) {
	case "", "user":
	default:
		return fmt.Errorf("authz clusterResolver source must be: user")
	}

	for key, cluster := range resolver.Mappings {
		if strings.TrimSpace(key) == "" {
			return fmt.Errorf("authz clusterResolver mappings cannot contain empty keys")
		}
		if strings.TrimSpace(cluster) == "" {
			return fmt.Errorf("authz clusterResolver mappings cannot contain empty cluster values")
		}
	}

	return nil
}

func (c *Config) validateAudit() error {
	if c.Audit.Enabled {
		if c.Audit.Store == "" {
			return fmt.Errorf("audit store is required when audit logging is enabled")
		}
		if c.Audit.Store != "memory" {
			return fmt.Errorf("audit store must be: memory")
		}
	}

	return nil
}

func (c *Config) validateBackends() error {
	if len(c.Backends) == 0 {
		return fmt.Errorf("at least one backend is required")
	}

	for name, backend := range c.Backends {
		if err := c.validateBackend(name, backend); err != nil {
			return err
		}
	}

	return nil
}

func (c *Config) validateBackend(name string, backend BackendConfig) error {
	if backend.Endpoint == "" {
		return fmt.Errorf("backend '%s' endpoint is required", name)
	}
	if backend.Type == "" {
		return fmt.Errorf("backend '%s' type is required", name)
	}
	if err := validateExternalPathPrefixes(name, backend); err != nil {
		return err
	}
	if err := c.validateNamespaceRouting(name, backend); err != nil {
		return err
	}
	if err := queryrewrite.Validate(name, backend.QueryRewrite); err != nil {
		return err
	}

	return nil
}

func validateExternalPathPrefixes(name string, backend BackendConfig) error {
	if len(backend.ExternalPathPrefixes) == 0 {
		return nil
	}
	if strings.TrimSpace(backend.ExternalHost) == "" {
		return fmt.Errorf("backend '%s' externalHost is required when externalPathPrefixes are configured", name)
	}
	for _, prefix := range backend.ExternalPathPrefixes {
		trimmedPrefix := strings.TrimSpace(prefix)
		if trimmedPrefix == "" {
			return fmt.Errorf("backend '%s' externalPathPrefixes cannot contain empty values", name)
		}
		if !strings.HasPrefix(trimmedPrefix, "/") {
			return fmt.Errorf("backend '%s' externalPathPrefixes values must start with '/'", name)
		}
	}

	return nil
}

func (c *Config) validateNamespaceRouting(name string, backend BackendConfig) error {
	if backend.NamespaceRouting == nil || backend.NamespaceRouting.Mode == "" {
		return nil
	}

	switch backend.NamespaceRouting.Mode {
	case "fixed":
		if strings.TrimSpace(backend.Namespace) == "" {
			return fmt.Errorf("backend '%s' namespace is required when namespaceRouting mode is fixed", name)
		}
	case "caller":
		if !c.Authz.ClusterResolver.HasMappings() {
			return fmt.Errorf("backend '%s' namespaceRouting mode caller requires authz.clusterResolver mappings", name)
		}
	case "request":
		if backend.NamespaceRouting.Parameter == "" {
			return fmt.Errorf("backend '%s' namespaceRouting parameter is required when mode is request", name)
		}
		switch strings.ToLower(strings.TrimSpace(backend.NamespaceRouting.Source)) {
		case "", "query", "body", "both":
		default:
			return fmt.Errorf("backend '%s' namespaceRouting source must be one of: query, body, both", name)
		}
		if strings.TrimSpace(backend.Namespace) != "" && !c.Authz.NamespaceClassifier.HasRules() {
			return fmt.Errorf("backend '%s' namespace requires authz.namespaceClassifier when namespaceRouting mode is request", name)
		}
	default:
		return fmt.Errorf("backend '%s' namespaceRouting mode must be one of: fixed, request, caller", name)
	}

	return nil
}
