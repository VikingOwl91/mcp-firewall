package proxy_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/VikingOwl91/mcp-firewall/internal/config"
	"github.com/VikingOwl91/mcp-firewall/internal/proxy"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupProxyFromResolvedConfig creates a proxy using ResolveConfig output,
// connecting in-memory downstreams, and returning a client session.
func setupProxyFromResolvedConfig(
	t *testing.T,
	cfg *config.Config,
	opts []proxy.ProxyOption,
	downstreams ...downstreamSetup,
) *mcp.ClientSession {
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

func TestE2E_ProfileStrictDeniesUnknownTools(t *testing.T) {
	type EmptyInput struct{}

	resolved, err := config.ResolveConfig("../../testdata/config/profiles.yaml", "strict", "")
	require.NoError(t, err)

	session := setupProxyFromResolvedConfig(t, resolved.Config,
		[]proxy.ProxyOption{proxy.WithProvenance("strict", "")},
		downstreamSetup{
			alias: "echoserver",
			setup: func(s *mcp.Server) {
				mcp.AddTool(s, &mcp.Tool{Name: "echo"}, func(_ context.Context, _ *mcp.CallToolRequest, _ EmptyInput) (*mcp.CallToolResult, any, error) {
					return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "should not reach without approval"}}}, nil, nil
				})
			},
		},
	)

	// strict profile has default:deny + prompt-all-tools → tool call should require approval
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "echoserver__echo"})
	require.NoError(t, err)
	assert.True(t, result.IsError)
	text := result.Content[0].(*mcp.TextContent)
	assert.Contains(t, text.Text, "requires user approval")
}

func TestE2E_DevProfileAllowsAll(t *testing.T) {
	type EmptyInput struct{}

	resolved, err := config.ResolveConfig("../../testdata/config/profiles.yaml", "development", "")
	require.NoError(t, err)

	session := setupProxyFromResolvedConfig(t, resolved.Config,
		[]proxy.ProxyOption{proxy.WithProvenance("development", "")},
		downstreamSetup{
			alias: "echoserver",
			setup: func(s *mcp.Server) {
				mcp.AddTool(s, &mcp.Tool{Name: "anything"}, func(_ context.Context, _ *mcp.CallToolRequest, _ EmptyInput) (*mcp.CallToolResult, any, error) {
					return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "allowed"}}}, nil, nil
				})
			},
		},
	)

	// development profile has default:allow → any tool call should succeed
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "echoserver__anything"})
	require.NoError(t, err)
	assert.False(t, result.IsError)
	text := result.Content[0].(*mcp.TextContent)
	assert.Equal(t, "allowed", text.Text)
}

func TestE2E_LocalOverrideDeniesBeforeBaseAllows(t *testing.T) {
	type EmptyInput struct{}

	workDir := t.TempDir()
	require.NoError(t, os.WriteFile(
		filepath.Join(workDir, ".mcp-firewall.yaml"),
		[]byte(`
policy:
  rules:
    - name: block-echo
      expression: 'tool.name == "echo"'
      effect: deny
`),
		0644,
	))

	resolved, err := config.ResolveConfig("../../testdata/config/profiles.yaml", "", workDir)
	require.NoError(t, err)

	localPath := filepath.Join(workDir, ".mcp-firewall.yaml")
	session := setupProxyFromResolvedConfig(t, resolved.Config,
		[]proxy.ProxyOption{proxy.WithProvenance("", localPath)},
		downstreamSetup{
			alias: "echoserver",
			setup: func(s *mcp.Server) {
				mcp.AddTool(s, &mcp.Tool{Name: "echo"}, func(_ context.Context, _ *mcp.CallToolRequest, _ EmptyInput) (*mcp.CallToolResult, any, error) {
					return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "should not reach"}}}, nil, nil
				})
			},
		},
	)

	// Base profile has allow-echo rule, but local override prepends block-echo deny
	// First-match-wins → deny should win
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "echoserver__echo"})
	require.NoError(t, err)
	assert.True(t, result.IsError)
	text := result.Content[0].(*mcp.TextContent)
	assert.Contains(t, text.Text, "denied by policy")
}

func TestE2E_ExplainToolShowsFullProvenance(t *testing.T) {
	workDir := t.TempDir()
	require.NoError(t, os.WriteFile(
		filepath.Join(workDir, ".mcp-firewall.yaml"),
		[]byte(`
policy:
  rules:
    - name: local-deny-rm
      expression: 'tool.name == "rm"'
      effect: deny
redaction:
  patterns:
    - name: project-key
      pattern: 'PROJ_[a-z]+'
timeout: 10s
`),
		0644,
	))

	resolved, err := config.ResolveConfig("../../testdata/config/valid.yaml", "", workDir)
	require.NoError(t, err)

	localPath := filepath.Join(workDir, ".mcp-firewall.yaml")
	session := setupProxyFromResolvedConfig(t, resolved.Config,
		[]proxy.ProxyOption{proxy.WithProvenance("", localPath)},
		downstreamSetup{
			alias: "echoserver",
			setup: func(s *mcp.Server) {},
		},
		downstreamSetup{
			alias: "another",
			setup: func(s *mcp.Server) {},
		},
	)

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "explain_effective_policy",
	})
	require.NoError(t, err)
	require.False(t, result.IsError)

	text := result.Content[0].(*mcp.TextContent)

	var output map[string]any
	require.NoError(t, json.Unmarshal([]byte(text.Text), &output))

	// Check local override path present
	assert.Equal(t, localPath, output["local_override"])

	// Check policy section
	pol := output["policy"].(map[string]any)
	assert.Equal(t, "deny", pol["default"])

	rules := pol["rules"].([]any)
	require.Len(t, rules, 2)

	// First rule: local deny
	r0 := rules[0].(map[string]any)
	assert.Equal(t, "local-deny-rm", r0["name"])
	assert.Equal(t, "deny", r0["effect"])
	assert.Equal(t, "local", r0["source"])

	// Second rule: base allow
	r1 := rules[1].(map[string]any)
	assert.Equal(t, "allow-echo", r1["name"])
	assert.Equal(t, "allow", r1["effect"])
	assert.Equal(t, "base", r1["source"])

	// Check redaction section
	red := output["redaction"].(map[string]any)
	pats := red["patterns"].([]any)
	require.Len(t, pats, 2)

	p0 := pats[0].(map[string]any)
	assert.Equal(t, "api-key", p0["name"])
	assert.Equal(t, "base", p0["source"])

	p1 := pats[1].(map[string]any)
	assert.Equal(t, "project-key", p1["name"])
	assert.Equal(t, "local", p1["source"])

	// Timeout should be the merged value (10s from local, lower than 30s base)
	assert.Equal(t, "10s", output["timeout"])
}

func TestE2E_ExplainToolShowsProfileProvenance(t *testing.T) {
	resolved, err := config.ResolveConfig("../../testdata/config/profiles.yaml", "strict", "")
	require.NoError(t, err)

	session := setupProxyFromResolvedConfig(t, resolved.Config,
		[]proxy.ProxyOption{proxy.WithProvenance("strict", "")},
		downstreamSetup{
			alias: "echoserver",
			setup: func(s *mcp.Server) {},
		},
	)

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "explain_effective_policy",
	})
	require.NoError(t, err)

	text := result.Content[0].(*mcp.TextContent)

	var output map[string]any
	require.NoError(t, json.Unmarshal([]byte(text.Text), &output))

	assert.Equal(t, "strict", output["profile"])

	pol := output["policy"].(map[string]any)
	rules := pol["rules"].([]any)
	require.Len(t, rules, 1)

	r0 := rules[0].(map[string]any)
	assert.Equal(t, "prompt-all-tools", r0["name"])
	assert.Equal(t, "profile:strict", r0["source"])
}

func TestE2E_LocalRedactionActuallyRedacts(t *testing.T) {
	type Input struct {
		Data string `json:"data"`
	}

	workDir := t.TempDir()
	require.NoError(t, os.WriteFile(
		filepath.Join(workDir, ".mcp-firewall.yaml"),
		[]byte(`
redaction:
  patterns:
    - name: project-token
      pattern: 'TOKEN_[A-Za-z0-9]+'
`),
		0644,
	))

	resolved, err := config.ResolveConfig("../../testdata/config/valid.yaml", "", workDir)
	require.NoError(t, err)

	var receivedData string
	session := setupProxyFromResolvedConfig(t, resolved.Config, nil,
		downstreamSetup{
			alias: "echoserver",
			setup: func(s *mcp.Server) {
				mcp.AddTool(s, &mcp.Tool{Name: "echo"}, func(_ context.Context, _ *mcp.CallToolRequest, input Input) (*mcp.CallToolResult, any, error) {
					receivedData = input.Data
					return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ok"}}}, nil, nil
				})
			},
		},
		downstreamSetup{
			alias: "another",
			setup: func(s *mcp.Server) {},
		},
	)

	// The tool call should have its arguments redacted by the local pattern
	_, err = session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "echoserver__echo",
		Arguments: map[string]any{"data": "my key is TOKEN_abc123xyz"},
	})
	require.NoError(t, err)

	// Both base (sk-...) and local (TOKEN_...) redaction should be active
	assert.Equal(t, "my key is [REDACTED]", receivedData)
}

func TestE2E_LocalOutputRedaction(t *testing.T) {
	type EmptyInput struct{}

	workDir := t.TempDir()
	require.NoError(t, os.WriteFile(
		filepath.Join(workDir, ".mcp-firewall.yaml"),
		[]byte(`
redaction:
  patterns:
    - name: project-token
      pattern: 'TOKEN_[A-Za-z0-9]+'
`),
		0644,
	))

	resolved, err := config.ResolveConfig("../../testdata/config/valid.yaml", "", workDir)
	require.NoError(t, err)

	session := setupProxyFromResolvedConfig(t, resolved.Config, nil,
		downstreamSetup{
			alias: "echoserver",
			setup: func(s *mcp.Server) {
				mcp.AddTool(s, &mcp.Tool{Name: "echo"}, func(_ context.Context, _ *mcp.CallToolRequest, _ EmptyInput) (*mcp.CallToolResult, any, error) {
					// Tool output contains both base-pattern and local-pattern secrets
					return &mcp.CallToolResult{Content: []mcp.Content{
						&mcp.TextContent{Text: "base secret sk-abcdefghijklmnopqrstuvwxyz123456 and local secret TOKEN_xyz789"},
					}}, nil, nil
				})
			},
		},
		downstreamSetup{
			alias: "another",
			setup: func(s *mcp.Server) {},
		},
	)

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "echoserver__echo",
	})
	require.NoError(t, err)

	text := result.Content[0].(*mcp.TextContent)
	assert.Equal(t, "base secret [REDACTED] and local secret [REDACTED]", text.Text)
}
