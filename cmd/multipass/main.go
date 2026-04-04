package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/karloie/multipass/internal/audit"
	"github.com/karloie/multipass/internal/auth"
	"github.com/karloie/multipass/internal/authz"
	"github.com/karloie/multipass/internal/config"
	"github.com/karloie/multipass/internal/pim"
	"github.com/karloie/multipass/internal/proxy"
	"github.com/karloie/multipass/internal/status"
)

var (
	version = "v0.0.1"
	commit  = "unknown"
)

const (
	providerOIDC  = "oidc"
	providerToken = "token"

	storeMemory = "memory"

	logLevelEnvVar  = "MULTIPASS_LOG_LEVEL"
	logFormatEnvVar = "MULTIPASS_LOG_FORMAT"

	logFormatJSON = "json"
	logFormatText = "text"
)

func main() {
	if err := configureLogging(); err != nil {
		slog.Error("invalid logging configuration", slog.Any("error", err))
		os.Exit(1)
	}

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [flags] <config-file>\n\n", os.Args[0])
		fmt.Fprintln(flag.CommandLine.Output(), "Flags:")
		flag.PrintDefaults()
	}

	showVersion := flag.Bool("version", false, "show version information")
	flag.Parse()

	if *showVersion {
		slog.Info("version", slog.String("version", version), slog.String("commit", commit))
		os.Exit(0)
	}

	configPath, err := parseConfigPath(flag.Args())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		flag.Usage()
		os.Exit(2)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		fatal("failed to load config", err)
	}

	if err := cfg.Validate(); err != nil {
		fatal("invalid configuration", err)
	}

	authProvider, err := initializeAuthProvider(cfg)
	if err != nil {
		fatal("failed to initialize auth provider", err)
	}

	sessionTTL, err := getSessionTTL(cfg)
	if err != nil {
		fatal("invalid auth session TTL", err)
	}

	sessionStore, err := initializeSessionStore(cfg, sessionTTL)
	if err != nil {
		fatal("failed to initialize session store", err)
	}
	defer func() {
		if err := sessionStore.Close(); err != nil {
			slog.Error("failed to close session store", slog.Any("error", err))
		}
	}()

	browserAuth := auth.NewHandlerWithPaths(authProvider, sessionStore, sessionTTL, cfg.Server.TrustForwardedProto, auth.PathsConfig{
		LoginPath:    cfg.Auth.OIDC.Paths().LoginPath,
		CallbackPath: cfg.Auth.OIDC.Paths().CallbackPath,
		LogoutPath:   cfg.Auth.OIDC.Paths().LogoutPath,
	})

	var pimStore *pim.MemoryStore
	if cfg.PIM.Enabled {
		pimStore = pim.NewMemoryStore()
		slog.Info("privileged access requests enabled", slog.Int("roles", len(cfg.PIM.Roles)))
	}

	evaluator, err := initializeAuthzProvider(cfg, sessionTTL, pimStore)
	if err != nil {
		fatal("failed to initialize authz provider", err)
	}

	auditStore, err := initializeAuditStore(cfg)
	if err != nil {
		fatal("failed to initialize audit store", err)
	}

	if auditStore != nil {
		defer func() {
			if err := auditStore.Close(); err != nil {
				slog.Error("failed to close audit store", slog.Any("error", err))
			}
		}()
	}

	handler, err := proxy.New(cfg, authProvider, browserAuth, evaluator, auditStore)
	if err != nil {
		fatal("failed to create proxy", err)
	}

	rootMux := http.NewServeMux()
	if status.Enabled(cfg) {
		rootMux.Handle("/status", status.NewHandler(cfg, browserAuth, evaluator))
		slog.Info("enabled diagnostics endpoint", slog.String("path", "/status"))
	}
	browserAuth.RegisterRoutes(rootMux)
	if cfg.PIM.Enabled {
		pimHandler, err := pim.NewHandler(cfg.PIM, cfg.Server.TrustForwardedProto, browserAuth, pimStore, auditStore, evaluator)
		if err != nil {
			fatal("failed to initialize pim handler", err)
		}
		pimHandler.RegisterRoutes(rootMux)
		slog.Info("enabled privileged access routes", slog.String("request_path", "/pim"), slog.String("approval_path", "/approve-pim"))
	}
	rootMux.Handle("/", handler)

	addr := fmt.Sprintf(":%d", cfg.Server.Port)
	slog.Info("starting multipass gateway",
		slog.String("address", addr),
		slog.Any("backends", cfg.GetBackendNames()),
		slog.String("auth_provider", cfg.Auth.Provider),
	)

	if err := http.ListenAndServe(addr, rootMux); err != nil {
		fatal("server failed", err)
	}
}

func configureLogging() error {
	level, err := getLogLevel()
	if err != nil {
		bootstrapLogger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
		slog.SetDefault(bootstrapLogger)
		return err
	}

	handler, err := getLogHandler(level)
	if err != nil {
		bootstrapLogger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
		slog.SetDefault(bootstrapLogger)
		return err
	}

	logger := slog.New(handler)
	slog.SetDefault(logger)
	return nil
}

func getLogLevel() (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(logLevelEnvVar))) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("%s must be one of: debug, info, warn, error", logLevelEnvVar)
	}
}

func getLogHandler(level slog.Level) (slog.Handler, error) {
	formatValue := strings.ToLower(strings.TrimSpace(os.Getenv(logFormatEnvVar)))
	handlerOptions := &slog.HandlerOptions{Level: level}

	if formatValue == "" || formatValue == logFormatJSON {
		return slog.NewJSONHandler(os.Stdout, handlerOptions), nil
	}

	switch formatValue {
	case logFormatText:
		return slog.NewTextHandler(os.Stdout, handlerOptions), nil
	default:
		return nil, fmt.Errorf("%s must be one of: json, text", logFormatEnvVar)
	}
}

func fatal(message string, err error) {
	slog.Error(message, slog.Any("error", err))
	os.Exit(1)
}

func parseConfigPath(args []string) (string, error) {
	if len(args) != 1 {
		return "", fmt.Errorf("expected exactly 1 config file argument")
	}

	configPath := strings.TrimSpace(args[0])
	if configPath == "" {
		return "", fmt.Errorf("config file argument must not be empty")
	}

	return configPath, nil
}

func getSessionTTL(cfg *config.Config) (time.Duration, error) {
	if cfg.Auth.SessionTTL == "" {
		return 24 * time.Hour, nil
	}

	ttl, err := time.ParseDuration(cfg.Auth.SessionTTL)
	if err != nil {
		return 0, err
	}
	if ttl <= 0 {
		return 0, fmt.Errorf("session TTL must be positive")
	}

	return ttl, nil
}

func initializeSessionStore(cfg *config.Config, sessionTTL time.Duration) (auth.SessionStore, error) {
	switch cfg.Auth.SessionStore.Store {
	case "", storeMemory:
		slog.Info("using session store", slog.String("store", storeMemory))
		return auth.NewMemorySessionStore(sessionTTL), nil
	default:
		return nil, fmt.Errorf("unknown session store '%s' (supported: memory)", cfg.Auth.SessionStore.Store)
	}
}

func initializeAuthProvider(cfg *config.Config) (auth.Provider, error) {
	switch cfg.Auth.Provider {
	case providerOIDC:
		provider, err := auth.NewOIDCProvider(auth.OIDCConfig{
			ProviderName:          cfg.Auth.OIDC.ProviderName,
			IssuerURL:             cfg.Auth.OIDC.IssuerURL,
			ClientID:              cfg.Auth.OIDC.ClientID,
			ClientSecret:          cfg.Auth.OIDC.ClientSecret,
			RedirectURL:           cfg.Auth.OIDC.RedirectURL,
			PostLogoutRedirectURL: cfg.Auth.OIDC.EffectivePostLogoutRedirectURL(),
			Scopes:                cfg.Auth.OIDC.Scopes,
		})
		if err != nil {
			return nil, fmt.Errorf("initializing OIDC provider: %w", err)
		}
		slog.Info("using oidc auth provider",
			slog.String("providerName", cfg.Auth.OIDC.ProviderName),
			slog.String("issuerUrl", cfg.Auth.OIDC.IssuerURL),
		)
		return provider, nil

	default:
		return nil, fmt.Errorf("unknown auth provider '%s' (supported: oidc)", cfg.Auth.Provider)
	}
}

func initializeAuthzProvider(cfg *config.Config, sessionTTL time.Duration, pimRoleProvider authz.ElevatedRoleProvider) (*authz.PolicyEvaluator, error) {
	if !cfg.Authz.Enabled {
		slog.Info("authorization disabled")
		return nil, nil
	}

	var groupProvider authz.GroupProvider
	var roleProvider authz.ElevatedRoleProvider

	switch cfg.Authz.Provider {
	case providerToken:
		tokenProvider := authz.NewTokenProvider()
		groupProvider = tokenProvider
		roleProvider = authz.NewCompositeRoleProvider(tokenProvider, pimRoleProvider)
		if cfg.Auth.TrustedProxy.Enabled {
			groupProvider = authz.NewCachedGroupProvider(groupProvider, authz.NewMemoryGroupCache(sessionTTL))
		}

	default:
		return nil, fmt.Errorf("unknown authz provider '%s' (supported: token)", cfg.Authz.Provider)
	}

	evaluator := authz.NewPolicyEvaluatorWithRoleMappings(groupProvider, roleProvider, cfg.Authz.GroupMappings, cfg.Authz.RoleMappings)
	slog.Info("authorization enabled", slog.String("provider", cfg.Authz.Provider))
	return evaluator, nil
}

func initializeAuditStore(cfg *config.Config) (audit.Store, error) {
	if !cfg.Audit.Enabled {
		slog.Info("audit logging disabled")
		return nil, nil
	}

	var store audit.Store

	switch cfg.Audit.Store {
	case storeMemory:
		store = audit.NewMemoryStore()
		slog.Info("using audit store", slog.String("store", storeMemory))

	default:
		return nil, fmt.Errorf("unknown audit store '%s' (supported: memory)", cfg.Audit.Store)
	}

	slog.Info("audit logging enabled", slog.String("store", cfg.Audit.Store))
	return store, nil
}
