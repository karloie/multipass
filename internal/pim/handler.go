package pim

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/karloie/multipass/internal/audit"
	"github.com/karloie/multipass/internal/auth"
	"github.com/karloie/multipass/internal/authz"
	"github.com/karloie/multipass/internal/config"
)

const (
	defaultRequestDuration = 30 * time.Minute
	requestPath            = "/pim"
	approvalPath           = "/pim/approve"
)

type browserAuthenticator interface {
	AuthenticateRequest(r *http.Request) (*auth.UserInfo, bool)
	LoginURL(returnTo string) string
}

type cacheInvalidator interface {
	InvalidateUserID(userID string)
}

type Handler struct {
	browserAuth         browserAuthenticator
	store               *MemoryStore
	auditStore          audit.Store
	trustForwardedProto bool
	evaluator           authz.Evaluator
	invalidator         cacheInvalidator
	defaultDuration     time.Duration
	allowSelfApproval   bool
	roles               []roleDefinition
	rolesByName         map[string]roleDefinition
	requestTemplate     *template.Template
	approvalTemplate    *template.Template
}

type roleDefinition struct {
	Name           string
	Approver       string
	ApproverGroups []string
	MaxDuration    time.Duration
}

type requestPageData struct {
	Title           string
	UserLabel       string
	Error           string
	Success         string
	Roles           []roleView
	Requests        []requestView
	DefaultMinutes  int
	RequestPath     string
	ApprovalPath    string
	SelectedRole    string
	SelectedMinutes int
	Reason          string
}

type approvalPageData struct {
	Title        string
	UserLabel    string
	Error        string
	Success      string
	Pending      []requestView
	RequestPath  string
	ApprovalPath string
}

type roleView struct {
	Name       string
	Approver   string
	MaxMinutes int
	Selected   bool
}

type requestView struct {
	ID               string
	RequesterLabel   string
	RequestedRole    string
	AssignedApprover string
	Reason           string
	DurationLabel    string
	Status           string
	CreatedAt        string
	DecisionAt       string
	DecidedBy        string
	ExpiresAt        string
}

func NewHandler(cfg config.PIMConfig, trustForwardedProto bool, browserAuth browserAuthenticator, store *MemoryStore, auditStore audit.Store, invalidator cacheInvalidator) (*Handler, error) {
	return NewHandlerWithEvaluator(cfg, trustForwardedProto, browserAuth, store, auditStore, nil, invalidator)
}

func NewHandlerWithEvaluator(cfg config.PIMConfig, trustForwardedProto bool, browserAuth browserAuthenticator, store *MemoryStore, auditStore audit.Store, evaluator authz.Evaluator, invalidator cacheInvalidator) (*Handler, error) {
	if browserAuth == nil {
		return nil, fmt.Errorf("browser authentication is required for pim")
	}
	if store == nil {
		return nil, fmt.Errorf("pim store is required")
	}

	defaultDuration := defaultRequestDuration
	if strings.TrimSpace(cfg.DefaultDuration) != "" {
		parsedDuration, err := time.ParseDuration(strings.TrimSpace(cfg.DefaultDuration))
		if err != nil {
			return nil, fmt.Errorf("parse pim defaultDuration: %w", err)
		}
		defaultDuration = parsedDuration
	}

	roles := make([]roleDefinition, 0, len(cfg.Roles))
	rolesByName := make(map[string]roleDefinition, len(cfg.Roles))
	for roleName, roleCfg := range cfg.Roles {
		maxDuration := defaultDuration
		if strings.TrimSpace(roleCfg.MaxDuration) != "" {
			parsedDuration, err := time.ParseDuration(strings.TrimSpace(roleCfg.MaxDuration))
			if err != nil {
				return nil, fmt.Errorf("parse pim role maxDuration for %s: %w", roleName, err)
			}
			maxDuration = parsedDuration
		}

		role := roleDefinition{
			Name:           strings.TrimSpace(roleName),
			Approver:       strings.TrimSpace(roleCfg.Approver),
			ApproverGroups: normalizeApproverGroups(roleCfg.ApproverGroups),
			MaxDuration:    maxDuration,
		}
		roles = append(roles, role)
		rolesByName[role.Name] = role
	}

	sort.Slice(roles, func(i, j int) bool {
		return roles[i].Name < roles[j].Name
	})

	funcs := template.FuncMap{}
	requestTemplate, err := template.New("pim-request").Funcs(funcs).Parse(requestPageHTML)
	if err != nil {
		return nil, err
	}
	approvalTemplate, err := template.New("pim-approval").Funcs(funcs).Parse(approvalPageHTML)
	if err != nil {
		return nil, err
	}

	return &Handler{
		browserAuth:         browserAuth,
		store:               store,
		auditStore:          auditStore,
		trustForwardedProto: trustForwardedProto,
		evaluator:           evaluator,
		invalidator:         invalidator,
		defaultDuration:     defaultDuration,
		roles:               roles,
		rolesByName:         rolesByName,
		requestTemplate:     requestTemplate,
		approvalTemplate:    approvalTemplate,
	}, nil
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc(requestPath, h.handleRequests)
	mux.HandleFunc(requestPath+"/", h.handleRequests)
	mux.HandleFunc(approvalPath, h.handleApprovals)
	mux.HandleFunc(approvalPath+"/", h.handleApprovals)
}

func (h *Handler) handleRequests(w http.ResponseWriter, r *http.Request) {
	userInfo, ok := h.requireBrowserUser(w, r)
	if !ok {
		return
	}

	switch {
	case r.Method == http.MethodGet && r.URL.Path == requestPath:
		h.renderRequestPage(w, r, userInfo, "", flashMessage(r.URL.Query().Get("created"), "Request submitted."), "", 0, "")
		return
	case r.Method == http.MethodPost && r.URL.Path == requestPath+"/request":
		h.handleCreateRequest(w, r, userInfo)
		return
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) handleApprovals(w http.ResponseWriter, r *http.Request) {
	userInfo, ok := h.requireBrowserUser(w, r)
	if !ok {
		return
	}

	switch {
	case r.Method == http.MethodGet && r.URL.Path == approvalPath:
		h.renderApprovalPage(w, r, userInfo, "", flashMessage(r.URL.Query().Get("updated"), "Decision recorded."))
		return
	case r.Method == http.MethodPost:
		h.handleDecision(w, r, userInfo)
		return
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) handleCreateRequest(w http.ResponseWriter, r *http.Request, userInfo *auth.UserInfo) {
	if err := h.validateSameOrigin(r); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		h.renderRequestPage(w, r, userInfo, "Invalid form data.", "", "", 0, "")
		return
	}

	roleName := strings.TrimSpace(r.FormValue("role"))
	role, ok := h.rolesByName[roleName]
	if !ok {
		h.renderRequestPage(w, r, userInfo, "Select a valid role.", "", roleName, 0, strings.TrimSpace(r.FormValue("reason")))
		return
	}

	minutes, err := strconv.Atoi(strings.TrimSpace(r.FormValue("duration_minutes")))
	if err != nil || minutes <= 0 {
		h.renderRequestPage(w, r, userInfo, "Enter a valid duration in minutes.", "", roleName, 0, strings.TrimSpace(r.FormValue("reason")))
		return
	}

	duration := time.Duration(minutes) * time.Minute
	if duration > role.MaxDuration {
		h.renderRequestPage(w, r, userInfo, fmt.Sprintf("%s can only be requested for up to %d minutes.", role.Name, int(role.MaxDuration.Minutes())), "", roleName, minutes, strings.TrimSpace(r.FormValue("reason")))
		return
	}

	reason := strings.TrimSpace(r.FormValue("reason"))
	if reason == "" {
		h.renderRequestPage(w, r, userInfo, "Reason is required.", "", roleName, minutes, reason)
		return
	}
	if !h.allowSelfApproval && (matchesIdentity(userInfo, role.Approver) || strings.EqualFold(requestCacheKey(userInfo), role.Approver) || matchesAnyGroup(userInfo, role.ApproverGroups)) {
		w.WriteHeader(http.StatusBadRequest)
		h.renderRequestPage(w, r, userInfo, ErrSelfApproval.Error(), "", roleName, minutes, reason)
		return
	}

	// For self-approval mode, assign request to requester
	assignedApprover := role.Approver
	assignedApproverGroups := append([]string(nil), role.ApproverGroups...)
	if h.allowSelfApproval {
		assignedApprover = requestUserLabel(userInfo)
		assignedApproverGroups = nil
	}

	req, err := h.store.CreateRequest(r.Context(), &Request{
		RequesterID:            requestUserID(userInfo),
		RequesterLabel:         requestUserLabel(userInfo),
		RequesterCacheKey:      requestCacheKey(userInfo),
		RequestedRole:          role.Name,
		AssignedApprover:       assignedApprover,
		AssignedApproverGroups: assignedApproverGroups,
		Reason:                 reason,
		Duration:               duration,
	})
	if err != nil {
		statusCode := http.StatusBadRequest
		if errors.Is(err, ErrDuplicateRequest) {
			statusCode = http.StatusConflict
		}
		w.WriteHeader(statusCode)
		h.renderRequestPage(w, r, userInfo, err.Error(), "", roleName, minutes, reason)
		return
	}

	h.logAudit(r.Context(), userInfo, req.RequestedRole, http.StatusCreated, "")
	http.Redirect(w, r, requestPath+"?created=1", http.StatusSeeOther)
}

func (h *Handler) handleDecision(w http.ResponseWriter, r *http.Request, userInfo *auth.UserInfo) {
	if err := h.validateSameOrigin(r); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	trimmed := strings.TrimPrefix(r.URL.Path, approvalPath+"/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" {
		http.NotFound(w, r)
		return
	}

	requestID := strings.TrimSpace(parts[0])
	action := strings.TrimSpace(parts[1])
	approve := false
	switch action {
	case "approve":
		approve = true
	case "deny":
	default:
		http.NotFound(w, r)
		return
	}

	req, err := h.store.DecideRequest(r.Context(), requestID, userInfo, approve)
	if err != nil {
		statusCode := http.StatusBadRequest
		switch {
		case errors.Is(err, ErrRequestNotFound):
			statusCode = http.StatusNotFound
		case errors.Is(err, ErrApproverMismatch):
			statusCode = http.StatusForbidden
		case errors.Is(err, ErrRequestAlreadyClosed):
			statusCode = http.StatusConflict
		}
		w.WriteHeader(statusCode)
		h.renderApprovalPage(w, r, userInfo, err.Error(), "")
		return
	}

	if h.invalidator != nil && strings.TrimSpace(req.RequesterCacheKey) != "" {
		h.invalidator.InvalidateUserID(req.RequesterCacheKey)
	}

	h.logAudit(r.Context(), userInfo, req.RequestedRole, http.StatusOK, "")
	http.Redirect(w, r, approvalPath+"?updated=1", http.StatusSeeOther)
}

func (h *Handler) renderRequestPage(w http.ResponseWriter, r *http.Request, userInfo *auth.UserInfo, errMsg, successMsg, selectedRole string, selectedMinutes int, reason string) {
	requests, err := h.store.ListRequestsForUser(r.Context(), userInfo)
	if err != nil {
		http.Error(w, "Failed to load requests", http.StatusInternalServerError)
		return
	}

	if selectedMinutes <= 0 {
		selectedMinutes = int(h.defaultDuration.Minutes())
	}

	data := requestPageData{
		Title:           "Privilege Level Requests",
		UserLabel:       requestUserLabel(userInfo),
		Error:           errMsg,
		Success:         successMsg,
		Roles:           h.roleViews(selectedRole),
		Requests:        buildRequestViews(requests),
		DefaultMinutes:  int(h.defaultDuration.Minutes()),
		RequestPath:     requestPath,
		ApprovalPath:    approvalPath,
		SelectedRole:    selectedRole,
		SelectedMinutes: selectedMinutes,
		Reason:          reason,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.requestTemplate.Execute(w, data); err != nil {
		http.Error(w, "Failed to render page", http.StatusInternalServerError)
	}
}

func (h *Handler) renderApprovalPage(w http.ResponseWriter, r *http.Request, userInfo *auth.UserInfo, errMsg, successMsg string) {
	pending, err := h.store.ListPendingForApprover(r.Context(), userInfo)
	if err != nil {
		http.Error(w, "Failed to load requests", http.StatusInternalServerError)
		return
	}

	data := approvalPageData{
		Title:        "Approve Privilege Level Requests",
		UserLabel:    requestUserLabel(userInfo),
		Error:        errMsg,
		Success:      successMsg,
		Pending:      buildRequestViews(pending),
		RequestPath:  requestPath,
		ApprovalPath: approvalPath,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.approvalTemplate.Execute(w, data); err != nil {
		http.Error(w, "Failed to render page", http.StatusInternalServerError)
	}
}

func (h *Handler) roleViews(selectedRole string) []roleView {
	roles := make([]roleView, 0, len(h.roles))
	for _, role := range h.roles {
		roles = append(roles, roleView{
			Name:       role.Name,
			Approver:   displayApprover(role.Approver, role.ApproverGroups),
			MaxMinutes: int(role.MaxDuration.Minutes()),
			Selected:   role.Name == selectedRole,
		})
	}
	return roles
}

func buildRequestViews(requests []Request) []requestView {
	views := make([]requestView, 0, len(requests))
	for _, req := range requests {
		views = append(views, requestView{
			ID:               req.ID,
			RequesterLabel:   req.RequesterLabel,
			RequestedRole:    req.RequestedRole,
			AssignedApprover: displayApprover(req.AssignedApprover, req.AssignedApproverGroups),
			Reason:           req.Reason,
			DurationLabel:    formatDuration(req.Duration),
			Status:           req.Status,
			CreatedAt:        formatTimestamp(req.CreatedAt),
			DecisionAt:       formatTimestamp(req.DecidedAt),
			DecidedBy:        req.DecidedBy,
			ExpiresAt:        formatTimestamp(req.ExpiresAt),
		})
	}
	return views
}

func formatDuration(duration time.Duration) string {
	minutes := int(duration.Minutes())
	if minutes%60 == 0 {
		hours := minutes / 60
		if hours == 1 {
			return "1 hour"
		}
		return fmt.Sprintf("%d hours", hours)
	}
	return fmt.Sprintf("%d min", minutes)
}

func formatTimestamp(ts time.Time) string {
	if ts.IsZero() {
		return ""
	}
	return ts.UTC().Format("2006-01-02 15:04 UTC")
}

func flashMessage(flag, msg string) string {
	if strings.TrimSpace(flag) == "1" {
		return msg
	}
	return ""
}

func displayApprover(approver string, approverGroups []string) string {
	trimmedApprover := strings.TrimSpace(approver)
	if trimmedApprover != "" && len(approverGroups) == 0 {
		return trimmedApprover
	}
	if trimmedApprover == "" && len(approverGroups) > 0 {
		return strings.Join(approverGroups, ", ")
	}
	if trimmedApprover != "" && len(approverGroups) > 0 {
		return trimmedApprover + " or " + strings.Join(approverGroups, ", ")
	}
	return ""
}

func (h *Handler) requireBrowserUser(w http.ResponseWriter, r *http.Request) (*auth.UserInfo, bool) {
	userInfo, ok := h.browserAuth.AuthenticateRequest(r)
	if ok && userInfo != nil {
		return userInfo, true
	}

	http.Redirect(w, r, h.browserAuth.LoginURL(currentURL(r)), http.StatusFound)
	return nil, false
}

func currentURL(r *http.Request) string {
	if r == nil {
		return requestPath
	}
	if r.URL.RawQuery == "" {
		return r.URL.Path
	}
	return r.URL.Path + "?" + r.URL.RawQuery
}

func (h *Handler) validateSameOrigin(r *http.Request) error {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		origin = strings.TrimSpace(r.Referer())
	}
	if origin == "" {
		return fmt.Errorf("missing origin")
	}

	parsed, err := url.Parse(origin)
	if err != nil {
		return fmt.Errorf("invalid origin")
	}
	if !strings.EqualFold(parsed.Host, r.Host) {
		return fmt.Errorf("cross-site request rejected")
	}

	expectedScheme := "http"
	if auth.IsSecureRequest(r, h.trustForwardedProto) {
		expectedScheme = "https"
	}
	if parsed.Scheme != "" && !strings.EqualFold(parsed.Scheme, expectedScheme) {
		return fmt.Errorf("cross-site request rejected")
	}

	return nil
}

func (h *Handler) logAudit(ctx context.Context, userInfo *auth.UserInfo, role string, statusCode int, errorMessage string) {
	if h.auditStore == nil || userInfo == nil {
		return
	}

	_ = h.auditStore.Log(ctx, &audit.AuditEvent{
		Timestamp:  time.Now().UTC(),
		UserID:     requestUserID(userInfo),
		Backend:    "pim",
		Namespace:  role,
		StatusCode: statusCode,
		Error:      errorMessage,
	})
}

const requestPageHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{.Title}}</title>
  <style>
    :root { color-scheme: light; --bg:#f4f1e8; --panel:#fffdf8; --ink:#1f2430; --muted:#5e6656; --accent:#2442b5; --line:#d9d0be; --danger:#8f2d2d; --ok:#1f6b43; }
    * { box-sizing: border-box; }
    body { margin:0; font-family: Georgia, "Times New Roman", serif; background: radial-gradient(circle at top left, #fff7df, var(--bg) 48%); color:var(--ink); }
    main { max-width: 980px; margin: 0 auto; padding: 32px 20px 48px; }
    header { display:flex; justify-content:space-between; gap:16px; align-items:flex-end; margin-bottom:24px; }
    h1,h2 { margin:0 0 8px; }
    p { margin:0; color:var(--muted); }
    .panel { background:var(--panel); border:1px solid var(--line); border-radius:18px; padding:20px; box-shadow:0 18px 40px rgba(32,33,36,0.06); margin-bottom:20px; }
    .message { padding:12px 14px; border-radius:12px; margin-bottom:16px; }
    .error { background:#fce9e7; color:var(--danger); }
    .success { background:#e6f5eb; color:var(--ok); }
    form { display:grid; gap:14px; }
    label { display:grid; gap:6px; font-weight:600; }
    input, select, textarea, button { font:inherit; }
    input, select, textarea { width:100%; padding:10px 12px; border:1px solid var(--line); border-radius:10px; background:#fff; }
    textarea { min-height: 110px; resize: vertical; }
    button { border:0; border-radius:999px; padding:11px 18px; background:var(--accent); color:#fff; cursor:pointer; }
    table { width:100%; border-collapse: collapse; }
    th, td { text-align:left; padding:12px 10px; border-top:1px solid var(--line); vertical-align:top; }
    th { color:var(--muted); font-size:0.95rem; }
    .split { display:grid; grid-template-columns: 1.2fr 1fr; gap:20px; }
    .meta { font-size:0.95rem; color:var(--muted); }
    .nav { display:flex; gap:12px; }
    .nav a { color:var(--accent); text-decoration:none; }
    @media (max-width: 760px) { .split { grid-template-columns: 1fr; } header { flex-direction:column; align-items:flex-start; } table, thead, tbody, th, td, tr { display:block; } th { display:none; } td { padding:8px 0; border-top:0; } tr { border-top:1px solid var(--line); padding:10px 0; } }
  </style>
</head>
<body>
  <main>
    <header>
      <div>
        <p>Signed in as {{.UserLabel}}</p>
        <h1>{{.Title}}</h1>
		<p>Request a temporary role level change in Multipass.</p>
      </div>
      <nav class="nav">
        <a href="{{.RequestPath}}">Request access</a>
        <a href="{{.ApprovalPath}}">Approve requests</a>
      </nav>
    </header>

    <section class="panel">
      {{if .Error}}<div class="message error">{{.Error}}</div>{{end}}
      {{if .Success}}<div class="message success">{{.Success}}</div>{{end}}
      <div class="split">
        <form action="{{.RequestPath}}/request" method="post">
          <label>
            Role
            <select name="role" required>
              <option value="">Select a role</option>
              {{range .Roles}}
              <option value="{{.Name}}" {{if .Selected}}selected{{end}}>{{.Name}} (approver: {{.Approver}}, max {{.MaxMinutes}} min)</option>
              {{end}}
            </select>
          </label>
          <label>
            Duration in minutes
            <input type="number" name="duration_minutes" min="5" step="5" value="{{.SelectedMinutes}}" required>
          </label>
          <label>
            Reason
            <textarea name="reason" placeholder="Why do you need temporary access?" required>{{.Reason}}</textarea>
          </label>
		  <button type="submit">Request level change</button>
        </form>
        <div>
          <h2>How it works</h2>
		  <p class="meta">Approved requests set one temporary role level at a time. A new approved level change replaces any currently active PIM level for that user.</p>
        </div>
      </div>
    </section>

    <section class="panel">
      <h2>Your requests</h2>
      {{if .Requests}}
      <table>
        <thead>
          <tr>
            <th>Role</th>
            <th>Status</th>
            <th>Approver</th>
            <th>Duration</th>
            <th>Created</th>
            <th>Decision</th>
          </tr>
        </thead>
        <tbody>
          {{range .Requests}}
          <tr>
            <td><strong>{{.RequestedRole}}</strong><br><span class="meta">{{.Reason}}</span></td>
            <td>{{.Status}}{{if .ExpiresAt}}<br><span class="meta">until {{.ExpiresAt}}</span>{{end}}</td>
            <td>{{.AssignedApprover}}</td>
            <td>{{.DurationLabel}}</td>
            <td>{{.CreatedAt}}</td>
            <td>{{if .DecisionAt}}{{.DecisionAt}}{{if .DecidedBy}}<br><span class="meta">by {{.DecidedBy}}</span>{{end}}{{end}}</td>
          </tr>
          {{end}}
        </tbody>
      </table>
      {{else}}
      <p class="meta">No requests yet.</p>
      {{end}}
    </section>
  </main>
</body>
</html>`

const approvalPageHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{.Title}}</title>
  <style>
    :root { color-scheme: light; --bg:#eef2f0; --panel:#ffffff; --ink:#1d2421; --muted:#5f6d67; --accent:#185a43; --deny:#8f2d2d; --line:#d5dfd9; --ok:#1f6b43; }
    * { box-sizing:border-box; }
    body { margin:0; font-family: Georgia, "Times New Roman", serif; background: linear-gradient(160deg, #f9fcfb 0%, var(--bg) 80%); color:var(--ink); }
    main { max-width: 980px; margin: 0 auto; padding: 32px 20px 48px; }
    header { display:flex; justify-content:space-between; gap:16px; align-items:flex-end; margin-bottom:24px; }
    .panel { background:var(--panel); border:1px solid var(--line); border-radius:18px; padding:20px; box-shadow:0 18px 40px rgba(32,33,36,0.06); }
    .message { padding:12px 14px; border-radius:12px; margin-bottom:16px; }
    .error { background:#fce9e7; color:var(--deny); }
    .success { background:#e6f5eb; color:var(--ok); }
    .nav { display:flex; gap:12px; }
    .nav a { color:var(--accent); text-decoration:none; }
    .card { border-top:1px solid var(--line); padding:16px 0; display:grid; gap:10px; }
    .card:first-of-type { border-top:0; padding-top:0; }
    .meta { color:var(--muted); }
    .actions { display:flex; gap:10px; }
    button { border:0; border-radius:999px; padding:11px 18px; color:#fff; cursor:pointer; font:inherit; }
    .approve { background:var(--accent); }
    .deny { background:var(--deny); }
    @media (max-width: 760px) { header { flex-direction:column; align-items:flex-start; } .actions { flex-direction:column; } }
  </style>
</head>
<body>
  <main>
    <header>
      <div>
        <p class="meta">Signed in as {{.UserLabel}}</p>
        <h1>{{.Title}}</h1>
        <p class="meta">Only requests explicitly assigned to you are shown here.</p>
      </div>
      <nav class="nav">
        <a href="{{.RequestPath}}">Request access</a>
        <a href="{{.ApprovalPath}}">Approve requests</a>
      </nav>
    </header>

    <section class="panel">
      {{if .Error}}<div class="message error">{{.Error}}</div>{{end}}
      {{if .Success}}<div class="message success">{{.Success}}</div>{{end}}
      {{if .Pending}}
        {{range .Pending}}
        <article class="card">
          <div><strong>{{.RequesterLabel}}</strong> requested <strong>{{.RequestedRole}}</strong> for {{.DurationLabel}}</div>
          <div class="meta">Requested {{.CreatedAt}}</div>
          <div>{{.Reason}}</div>
          <div class="actions">
            <form action="{{$.ApprovalPath}}/{{.ID}}/approve" method="post"><button class="approve" type="submit">Approve</button></form>
            <form action="{{$.ApprovalPath}}/{{.ID}}/deny" method="post"><button class="deny" type="submit">Deny</button></form>
          </div>
        </article>
        {{end}}
      {{else}}
        <p class="meta">No pending requests assigned to you.</p>
      {{end}}
    </section>
  </main>
</body>
</html>`
