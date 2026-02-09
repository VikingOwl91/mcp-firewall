package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/VikingOwl91/mcp-firewall/internal/config"
	"github.com/VikingOwl91/mcp-firewall/internal/proxy"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	home, err := os.UserHomeDir()
	if err != nil {
		slog.Error("failed to determine home directory", slog.String("error", err.Error()))
		os.Exit(1)
	}
	defaultConfig := filepath.Join(home, ".mcp-firewall", "config.yaml")

	configPath := flag.String("config", defaultConfig, "path to config file")
	profileName := flag.String("profile", "", "config profile name (env: MCP_FIREWALL_PROFILE)")
	workspacePath := flag.String("workspace", "", "workspace directory for local override (auto-detected if omitted)")
	flag.Parse()

	// Auto-detect workspace if not specified
	workspace := *workspacePath
	if workspace == "" {
		if cwd, err := os.Getwd(); err == nil {
			workspace = config.DetectWorkspace(cwd)
		}
	}

	resolved, err := config.ResolveConfig(*configPath, *profileName, workspace)
	if err != nil {
		slog.Error("failed to load config", slog.String("error", err.Error()))
		os.Exit(1)
	}

	level := parseLogLevel(resolved.Config.LogLevel)
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	p := proxy.New(resolved.Config, logger, proxy.WithProvenance(resolved.ProfileName, resolved.LocalOverride))

	if err := p.Run(ctx, &mcp.StdioTransport{}); err != nil {
		logger.Error("proxy exited with error", slog.String("error", err.Error()))
		os.Exit(1)
	}
}

func parseLogLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
