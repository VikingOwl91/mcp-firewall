package proxy_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/VikingOwl91/mcp-firewall/internal/config"
	"github.com/VikingOwl91/mcp-firewall/internal/proxy"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExplainPolicy_BaseOnly(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"echo": {Command: "unused"},
		},
		Policy: config.PolicyConfig{
			Default: "deny",
			Rules: []config.PolicyRule{
				{Name: "allow-echo", Expression: `tool.name == "echo"`, Effect: "allow", Source: "base"},
			},
		},
		Redaction: config.RedactionConfig{
			Patterns: []config.RedactionPattern{
				{Name: "api-key", Pattern: `sk-[a-zA-Z0-9]{32}`, Source: "base"},
			},
		},
	}
	cfg.Policy.Default = "deny"
	require.NoError(t, cfg.Validate())

	session := setupProxyWithConfigAndOpts(t, cfg, nil,
		downstreamSetup{
			alias: "echo",
			setup: func(s *mcp.Server) {},
		},
	)

	// List tools — explain_effective_policy should be present
	listResult, err := session.ListTools(context.Background(), nil)
	require.NoError(t, err)

	var found bool
	for _, tool := range listResult.Tools {
		if tool.Name == "explain_effective_policy" {
			found = true
			break
		}
	}
	assert.True(t, found, "explain_effective_policy tool should be listed")

	// Call the tool
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "explain_effective_policy",
	})
	require.NoError(t, err)
	require.False(t, result.IsError)
	require.NotEmpty(t, result.Content)

	text := result.Content[0].(*mcp.TextContent)

	// Should contain policy info
	assert.Contains(t, text.Text, "allow-echo")
	assert.Contains(t, text.Text, "deny")
	assert.Contains(t, text.Text, "api-key")
	assert.Contains(t, text.Text, "base")
}

func TestExplainPolicy_WithLocalOverride(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"echo": {Command: "unused"},
		},
		Policy: config.PolicyConfig{
			Default: "deny",
			Rules: []config.PolicyRule{
				{Name: "local-block", Expression: `tool.name == "rm"`, Effect: "deny", Source: "local"},
				{Name: "allow-echo", Expression: `tool.name == "echo"`, Effect: "allow", Source: "base"},
			},
		},
	}
	require.NoError(t, cfg.Validate())

	session := setupProxyWithConfigAndOpts(t, cfg,
		[]proxy.ProxyOption{proxy.WithProvenance("", "/workspace/.mcp-firewall.yaml")},
		downstreamSetup{
			alias: "echo",
			setup: func(s *mcp.Server) {},
		},
	)

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "explain_effective_policy",
	})
	require.NoError(t, err)

	text := result.Content[0].(*mcp.TextContent)
	assert.Contains(t, text.Text, "local-block")
	assert.Contains(t, text.Text, "local")
	assert.Contains(t, text.Text, "/workspace/.mcp-firewall.yaml")
}

func TestExplainPolicy_ShowsProfile(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"echo": {Command: "unused"},
		},
		Policy: config.PolicyConfig{
			Default: "deny",
		},
	}
	require.NoError(t, cfg.Validate())

	session := setupProxyWithConfigAndOpts(t, cfg,
		[]proxy.ProxyOption{proxy.WithProvenance("strict", "")},
		downstreamSetup{
			alias: "echo",
			setup: func(s *mcp.Server) {},
		},
	)

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "explain_effective_policy",
	})
	require.NoError(t, err)

	text := result.Content[0].(*mcp.TextContent)
	assert.Contains(t, text.Text, "strict")
}

// setupProxyWithConfigAndOpts creates a proxy with a full Config and optional ProxyOptions.
func setupProxyWithConfigAndOpts(t *testing.T, cfg *config.Config, opts []proxy.ProxyOption, downstreams ...downstreamSetup) *mcp.ClientSession {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	logger := slog.Default()

	p := proxy.New(cfg, logger, opts...)

	for _, ds := range downstreams {
		dsServer := mcp.NewServer(&mcp.Implementation{
			Name: "test-" + ds.alias, Version: "0.1.0",
		}, nil)
		ds.setup(dsServer)

		dsServerT, dsClientT := mcp.NewInMemoryTransports()
		_, err := dsServer.Connect(ctx, dsServerT, nil)
		require.NoError(t, err)

		err = p.ConnectDownstream(ctx, ds.alias, dsClientT)
		require.NoError(t, err)
	}

	err := p.RegisterUpstreamHandlers(ctx)
	require.NoError(t, err)

	upServerT, upClientT := mcp.NewInMemoryTransports()
	go func() { _ = p.ServeUpstream(ctx, upServerT) }()

	client := mcp.NewClient(&mcp.Implementation{
		Name: "test-client", Version: "0.1.0",
	}, nil)
	session, err := client.Connect(ctx, upClientT, nil)
	require.NoError(t, err)
	t.Cleanup(func() { session.Close() })

	return session
}

// Verify explain tool returns valid JSON
func TestExplainPolicy_ValidJSON(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"echo": {Command: "unused"},
		},
		Policy: config.PolicyConfig{
			Default: "deny",
			Rules: []config.PolicyRule{
				{Name: "allow-echo", Expression: `tool.name == "echo"`, Effect: "allow"},
			},
		},
	}
	require.NoError(t, cfg.Validate())

	session := setupProxyWithConfigAndOpts(t, cfg, nil,
		downstreamSetup{
			alias: "echo",
			setup: func(s *mcp.Server) {},
		},
	)

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "explain_effective_policy",
	})
	require.NoError(t, err)

	text := result.Content[0].(*mcp.TextContent)
	// Should be valid JSON
	var parsed map[string]any
	err = json.Unmarshal([]byte(text.Text), &parsed)
	require.NoError(t, err, "explain output should be valid JSON")
	assert.Contains(t, parsed, "policy")
}
