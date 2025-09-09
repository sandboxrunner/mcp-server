package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	
	"github.com/sandboxrunner/mcp-server/pkg/api"
	"github.com/sandboxrunner/mcp-server/pkg/config"
	"github.com/sandboxrunner/mcp-server/pkg/mcp"
	"github.com/sandboxrunner/mcp-server/pkg/runtime"
	"github.com/sandboxrunner/mcp-server/pkg/sandbox"
	"github.com/sandboxrunner/mcp-server/pkg/tools"
)

var (
	// Global flags
	configFile  string
	logLevel    string
	logFormat   string
	workspaceDir string
	enableHTTP  bool
	httpPort    int
	
	// Build info (set by build system)
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "mcp-sandboxd",
		Short: "SandboxRunner MCP Server",
		Long: `SandboxRunner MCP Server provides sandbox management capabilities
through the Model Context Protocol (MCP). It allows AI assistants to create,
manage, and interact with isolated sandbox environments.`,
		Version: fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, date),
		RunE:    runServer,
	}
	
	// Add flags
	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "", "config file path")
	rootCmd.PersistentFlags().StringVarP(&logLevel, "log-level", "l", "", "log level (debug, info, warn, error)")
	rootCmd.PersistentFlags().StringVarP(&logFormat, "log-format", "f", "", "log format (json, text, console)")
	rootCmd.PersistentFlags().StringVarP(&workspaceDir, "workspace-dir", "w", "", "sandbox workspace directory")
	rootCmd.PersistentFlags().BoolVar(&enableHTTP, "http", false, "enable HTTP server mode")
	rootCmd.PersistentFlags().IntVarP(&httpPort, "port", "p", 0, "HTTP server port")
	
	// Add subcommands
	rootCmd.AddCommand(newConfigCmd())
	rootCmd.AddCommand(newVersionCmd())
	
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runServer(cmd *cobra.Command, args []string) error {
	// Load configuration
	cfg, err := config.LoadConfig(configFile)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}
	
	// Override config with command line flags
	if logLevel != "" {
		cfg.Logging.Level = logLevel
	}
	if logFormat != "" {
		cfg.Logging.Format = logFormat
	}
	if workspaceDir != "" {
		cfg.Sandbox.WorkspaceDir = workspaceDir
	}
	if enableHTTP {
		cfg.Server.EnableHTTP = true
	}
	if httpPort > 0 {
		cfg.Server.Port = httpPort
	}
	
	// Setup logging
	logger, err := setupLogging(cfg.Logging)
	if err != nil {
		return fmt.Errorf("failed to setup logging: %w", err)
	}
	
	logger.Info().
		Str("version", version).
		Str("commit", commit).
		Str("build_date", date).
		Str("protocol", cfg.Server.Protocol).
		Bool("http_enabled", cfg.Server.EnableHTTP).
		Msg("Starting MCP SandboxRunner Server")
	
	// Create necessary directories
	if err := cfg.CreateDirectories(); err != nil {
		return fmt.Errorf("failed to create directories: %w", err)
	}
	
	// Initialize sandbox manager
	sandboxManager, err := sandbox.NewManager(cfg.Sandbox.DatabasePath, cfg.Sandbox.WorkspaceDir)
	if err != nil {
		return fmt.Errorf("failed to create sandbox manager: %w", err)
	}
	defer sandboxManager.Close()
	
	// Create tool registry and register tools
	toolRegistry := tools.NewRegistry()
	if err := registerTools(toolRegistry, sandboxManager, cfg); err != nil {
		return fmt.Errorf("failed to register tools: %w", err)
	}
	
	// Create MCP server
	serverConfig := mcp.ServerConfig{
		Name:         cfg.Server.Name,
		Version:      cfg.Server.Version,
		Logger:       &logger,
		ToolRegistry: toolRegistry,
	}
	
	mcpServer := mcp.NewServer(serverConfig)
	
	// Setup context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	// Setup signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	
	// Start server based on protocol
	errCh := make(chan error, 1)
	
	if cfg.Server.EnableHTTP {
		go func() {
			errCh <- runHTTPServer(ctx, mcpServer, cfg, logger, sandboxManager, toolRegistry)
		}()
	} else {
		go func() {
			errCh <- mcpServer.Run(ctx)
		}()
	}
	
	// Wait for shutdown signal or error
	select {
	case sig := <-sigCh:
		logger.Info().Str("signal", sig.String()).Msg("Received shutdown signal")
		cancel()
		
		// Give server time to shutdown gracefully
		select {
		case <-time.After(10 * time.Second):
			logger.Warn().Msg("Graceful shutdown timeout, forcing exit")
		case err := <-errCh:
			if err != nil {
				logger.Error().Err(err).Msg("Server shutdown with error")
			}
		}
		
	case err := <-errCh:
		if err != nil {
			logger.Error().Err(err).Msg("Server error")
			return err
		}
	}
	
	logger.Info().Msg("Server shutdown complete")
	return nil
}

func setupLogging(cfg config.LoggingConfig) (zerolog.Logger, error) {
	// Set log level
	level, err := zerolog.ParseLevel(cfg.Level)
	if err != nil {
		return zerolog.Logger{}, fmt.Errorf("invalid log level: %w", err)
	}
	zerolog.SetGlobalLevel(level)
	
	// Setup output
	var output *os.File
	if cfg.OutputFile != "" {
		// Create log directory if it doesn't exist
		logDir := filepath.Dir(cfg.OutputFile)
		if err := os.MkdirAll(logDir, 0755); err != nil {
			return zerolog.Logger{}, fmt.Errorf("failed to create log directory: %w", err)
		}
		
		file, err := os.OpenFile(cfg.OutputFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return zerolog.Logger{}, fmt.Errorf("failed to open log file: %w", err)
		}
		output = file
	} else {
		output = os.Stderr
	}
	
	// Setup logger based on format
	var logger zerolog.Logger
	switch cfg.Format {
	case "console":
		logger = log.Output(zerolog.ConsoleWriter{Out: output, TimeFormat: time.RFC3339})
	case "text":
		logger = zerolog.New(output).With().Timestamp().Logger()
	case "json":
		fallthrough
	default:
		logger = zerolog.New(output).With().Timestamp().Logger()
	}
	
	return logger, nil
}

func registerTools(registry *tools.Registry, manager *sandbox.Manager, cfg *config.Config) error {
	// Get list of enabled tools
	enabledTools := cfg.GetEnabledTools()
	
	// Create a default ContainerFS instance for tools that need it
	// In a real implementation, this might come from the runtime client
	var defaultContainerFS runtime.ContainerFS
	
	// Create and register tools
	toolCreators := map[string]func() tools.Tool{
		"create_sandbox":    func() tools.Tool { return tools.NewCreateSandboxTool(manager) },
		"list_sandboxes":    func() tools.Tool { return tools.NewListSandboxesTool(manager) },
		"terminate_sandbox": func() tools.Tool { return tools.NewTerminateSandboxTool(manager) },
		"exec_command":      func() tools.Tool { return tools.NewExecCommandTool(manager) },
		"run_code":          func() tools.Tool { return tools.NewRunCodeTool(manager) },
		"upload_file":       func() tools.Tool { return tools.NewUploadFileTool(manager, defaultContainerFS) },
		"download_file":     func() tools.Tool { return tools.NewDownloadFileTool(manager) },
		"list_files":        func() tools.Tool { return tools.NewListFilesTool(manager) },
		"read_file":         func() tools.Tool { return tools.NewReadFileTool(manager) },
		"write_file":        func() tools.Tool { return tools.NewWriteFileTool(manager) },
		// Language-specific tools
		"run_python":        func() tools.Tool { return tools.NewRunPythonTool(manager) },
		"run_javascript":    func() tools.Tool { return tools.NewRunJavaScriptTool(manager) },
		"run_typescript":    func() tools.Tool { return tools.NewRunTypeScriptTool(manager) },
		"run_go":            func() tools.Tool { return tools.NewRunGoTool(manager) },
		"run_rust":          func() tools.Tool { return tools.NewRunRustTool(manager) },
		"run_java":          func() tools.Tool { return tools.NewRunJavaTool(manager) },
		"run_cpp":           func() tools.Tool { return tools.NewRunCppTool(manager) },
		"run_csharp":        func() tools.Tool { return tools.NewRunCSharpTool(manager) },
		"run_shell":         func() tools.Tool { return tools.NewRunShellTool(manager) },
		"run_generic":       func() tools.Tool { return tools.NewRunGenericTool(manager) },
	}
	
	// Register enabled tools
	for _, toolName := range enabledTools {
		if creator, exists := toolCreators[toolName]; exists {
			tool := creator()
			if err := registry.RegisterTool(tool); err != nil {
				return fmt.Errorf("failed to register tool %s: %w", toolName, err)
			}
			log.Debug().Str("tool", toolName).Msg("Registered tool")
		} else {
			log.Warn().Str("tool", toolName).Msg("Unknown tool in enabled list")
		}
	}
	
	log.Info().Int("count", registry.Count()).Msg("Tools registered")
	return nil
}

func runHTTPServer(ctx context.Context, mcpServer *mcp.Server, cfg *config.Config, logger zerolog.Logger, sandboxManager *sandbox.Manager, toolRegistry *tools.Registry) error {
	// Create HTTP server configuration
	httpConfig := mcp.HTTPServerConfig{
		Address:              cfg.Server.Address,
		Port:                 cfg.Server.Port,
		ReadTimeout:          cfg.Server.ReadTimeout,
		WriteTimeout:         cfg.Server.WriteTimeout,
		EnableCORS:           true,
		CORSOrigins:          []string{"*"},
		CORSMethods:          []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		CORSHeaders:          []string{"Content-Type", "Authorization", "Accept", "Origin"},
		EnableCompression:    true,
		CompressionLevel:     6,
		CompressionMinSize:   1024,
		EnableMetrics:        true,
		EnableWebSocket:      true,
		WebSocketOriginCheck: false, // Allow all origins for development
		MaxConnections:       1000,
		MaxRequestSize:       10 * 1024 * 1024, // 10MB
		RateLimitRPS:         100,
		RateLimitBurst:       200,
	}
	
	// Create HTTP server with MCP support
	httpServer := mcp.NewHTTPServer(httpConfig, mcpServer, logger)
	
	// Create REST API
	apiConfig := api.RESTAPIConfig{
		BasePath:             "/api",
		DefaultPageSize:      20,
		MaxPageSize:          100,
		EnableVersioning:     true,
		SupportedVersions:    []api.APIVersion{api.V1, api.V2},
		DefaultVersion:       api.V1,
		EnableFiltering:      true,
		EnableSorting:        true,
		EnableFieldSelection: true,
		RequestTimeout:       30 * time.Second,
		MaxRetries:           3,
		EnableETag:           true,
		EnableRateLimit:      true,
		EnableValidation:     true,
	}
	
	restAPI := api.NewRESTAPI(apiConfig, sandboxManager, toolRegistry, mcpServer, logger)
	
	// Mount REST API routes onto HTTP server router
	httpServer.GetRouter().PathPrefix("/api").Handler(restAPI.GetRouter())
	
	logger.Info().
		Str("address", fmt.Sprintf("%s:%d", httpConfig.Address, httpConfig.Port)).
		Bool("websocket_enabled", httpConfig.EnableWebSocket).
		Bool("compression_enabled", httpConfig.EnableCompression).
		Bool("metrics_enabled", httpConfig.EnableMetrics).
		Bool("cors_enabled", httpConfig.EnableCORS).
		Str("api_base_path", apiConfig.BasePath).
		Strs("api_versions", apiVersionsToStrings(apiConfig.SupportedVersions)).
		Msg("Starting HTTP server with MCP and REST API support")
	
	// Start HTTP server
	if err := httpServer.Start(ctx); err != nil {
		return fmt.Errorf("failed to start HTTP server: %w", err)
	}
	
	// Wait for context cancellation
	<-ctx.Done()
	
	// Graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	
	logger.Info().Msg("Shutting down HTTP server")
	return httpServer.Stop(shutdownCtx)
}

func newConfigCmd() *cobra.Command {
	var outputPath string
	
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Configuration management commands",
	}
	
	// Generate default config
	generateCmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate default configuration file",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := config.DefaultConfig()
			
			if outputPath == "" {
				outputPath = "mcp-sandboxd.yaml"
			}
			
			if err := cfg.SaveConfig(outputPath); err != nil {
				return fmt.Errorf("failed to save config: %w", err)
			}
			
			fmt.Printf("Generated default configuration: %s\n", outputPath)
			return nil
		},
	}
	generateCmd.Flags().StringVarP(&outputPath, "output", "o", "", "output file path")
	
	// Validate config
	validateCmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate configuration file",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.LoadConfig(configFile)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}
			
			fmt.Printf("Configuration is valid\n")
			fmt.Printf("Server: %s v%s\n", cfg.Server.Name, cfg.Server.Version)
			fmt.Printf("Protocol: %s\n", cfg.Server.Protocol)
			fmt.Printf("Workspace: %s\n", cfg.Sandbox.WorkspaceDir)
			fmt.Printf("Enabled tools: %d\n", len(cfg.GetEnabledTools()))
			
			return nil
		},
	}
	
	cmd.AddCommand(generateCmd)
	cmd.AddCommand(validateCmd)
	
	return cmd
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("MCP SandboxRunner Server\n")
			fmt.Printf("Version: %s\n", version)
			fmt.Printf("Commit: %s\n", commit)
			fmt.Printf("Built: %s\n", date)
		},
	}
}

// Helper function to convert API versions to strings
func apiVersionsToStrings(versions []api.APIVersion) []string {
	strings := make([]string, len(versions))
	for i, v := range versions {
		strings[i] = string(v)
	}
	return strings
}