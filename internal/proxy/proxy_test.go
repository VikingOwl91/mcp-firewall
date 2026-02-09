package proxy_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/VikingOwl91/mcp-firewall/internal/config"
	"github.com/VikingOwl91/mcp-firewall/internal/proxy"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type downstreamSetup struct {
	alias string
	setup func(s *mcp.Server)
}

// setupProxy creates one or more downstream MCP servers, connects a proxy to them via
// in-memory transports, and returns a client session talking to the proxy's upstream side.
func setupProxy(t *testing.T, downstreams ...downstreamSetup) *mcp.ClientSession {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	logger := slog.Default()

	cfgDownstreams := make(map[string]config.ServerConfig)
	for _, ds := range downstreams {
		cfgDownstreams[ds.alias] = config.ServerConfig{Command: "unused"}
	}

	cfg := &config.Config{
		Downstreams: cfgDownstreams,
		LogLevel:    "debug",
	}
	cfg.Policy.Default = "allow" // default allow for non-policy tests
	require.NoError(t, cfg.Validate())

	p := proxy.New(cfg, logger)

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

func TestProxy_ToolListAndCall(t *testing.T) {
	type EchoInput struct {
		Message string `json:"message"`
	}

	session := setupProxy(t, downstreamSetup{
		alias: "echoserver",
		setup: func(s *mcp.Server) {
			mcp.AddTool(s, &mcp.Tool{
				Name:        "echo",
				Description: "echoes a message",
			}, func(_ context.Context, req *mcp.CallToolRequest, input EchoInput) (*mcp.CallToolResult, any, error) {
				return &mcp.CallToolResult{
					Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("echo: %s", input.Message)}},
				}, nil, nil
			})
		},
	})

	listResult, err := session.ListTools(context.Background(), nil)
	require.NoError(t, err)
	require.Len(t, listResult.Tools, 1)
	assert.Equal(t, "echoserver__echo", listResult.Tools[0].Name)
	assert.Equal(t, "echoes a message", listResult.Tools[0].Description)

	callResult, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "echoserver__echo",
		Arguments: map[string]any{"message": "hello"},
	})
	require.NoError(t, err)
	require.Len(t, callResult.Content, 1)

	text, ok := callResult.Content[0].(*mcp.TextContent)
	require.True(t, ok, "expected TextContent, got %T", callResult.Content[0])
	assert.Equal(t, "echo: hello", text.Text)
}

func TestProxy_ResourceListAndRead(t *testing.T) {
	session := setupProxy(t, downstreamSetup{
		alias: "files",
		setup: func(s *mcp.Server) {
			s.AddResource(&mcp.Resource{
				URI:  "test://hello",
				Name: "hello",
			}, func(_ context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
				return &mcp.ReadResourceResult{
					Contents: []*mcp.ResourceContents{{URI: req.Params.URI, Text: "Hello!"}},
				}, nil
			})
		},
	})

	listResult, err := session.ListResources(context.Background(), nil)
	require.NoError(t, err)
	require.Len(t, listResult.Resources, 1)
	assert.Equal(t, "test://hello", listResult.Resources[0].URI)
	assert.Equal(t, "files__hello", listResult.Resources[0].Name)

	readResult, err := session.ReadResource(context.Background(), &mcp.ReadResourceParams{
		URI: "test://hello",
	})
	require.NoError(t, err)
	require.Len(t, readResult.Contents, 1)
	assert.Equal(t, "Hello!", readResult.Contents[0].Text)
}

func TestProxy_NoToolsNoResources(t *testing.T) {
	session := setupProxy(t, downstreamSetup{
		alias: "empty",
		setup: func(s *mcp.Server) {},
	})

	listTools, err := session.ListTools(context.Background(), nil)
	require.NoError(t, err)
	assert.Empty(t, listTools.Tools)

	listRes, err := session.ListResources(context.Background(), nil)
	require.NoError(t, err)
	assert.Empty(t, listRes.Resources)
}

func TestProxy_DownstreamError(t *testing.T) {
	session := setupProxy(t, downstreamSetup{
		alias: "failing",
		setup: func(s *mcp.Server) {
			s.AddTool(&mcp.Tool{
				Name:        "fail",
				InputSchema: json.RawMessage(`{"type":"object"}`),
			}, func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				return &mcp.CallToolResult{
					Content: []mcp.Content{&mcp.TextContent{Text: "something went wrong"}},
					IsError: true,
				}, nil
			})
		},
	})

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "failing__fail",
	})
	require.NoError(t, err)
	assert.True(t, result.IsError)
	text := result.Content[0].(*mcp.TextContent)
	assert.Equal(t, "something went wrong", text.Text)
}

func TestProxy_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	logger := slog.Default()
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"test": {Command: "unused"},
		},
		LogLevel: "debug",
	}
	cfg.Policy.Default = "allow"

	downstream := mcp.NewServer(&mcp.Implementation{
		Name: "test-downstream", Version: "0.1.0",
	}, nil)

	dsServerT, dsClientT := mcp.NewInMemoryTransports()
	_, err := downstream.Connect(ctx, dsServerT, nil)
	require.NoError(t, err)

	p := proxy.New(cfg, logger)
	err = p.ConnectDownstream(ctx, "test", dsClientT)
	require.NoError(t, err)

	err = p.RegisterUpstreamHandlers(ctx)
	require.NoError(t, err)

	upServerT, _ := mcp.NewInMemoryTransports()

	done := make(chan error, 1)
	go func() {
		done <- p.ServeUpstream(ctx, upServerT)
	}()

	cancel()

	err = <-done
	if err != nil {
		assert.ErrorIs(t, err, context.Canceled)
	}
}

func TestProxy_MultipleDownstreams_ToolList(t *testing.T) {
	type EchoInput struct {
		Message string `json:"message"`
	}

	session := setupProxy(t,
		downstreamSetup{
			alias: "alpha",
			setup: func(s *mcp.Server) {
				mcp.AddTool(s, &mcp.Tool{Name: "greet"}, func(_ context.Context, _ *mcp.CallToolRequest, _ EchoInput) (*mcp.CallToolResult, any, error) {
					return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "hi from alpha"}}}, nil, nil
				})
			},
		},
		downstreamSetup{
			alias: "beta",
			setup: func(s *mcp.Server) {
				mcp.AddTool(s, &mcp.Tool{Name: "greet"}, func(_ context.Context, _ *mcp.CallToolRequest, _ EchoInput) (*mcp.CallToolResult, any, error) {
					return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "hi from beta"}}}, nil, nil
				})
			},
		},
	)

	listResult, err := session.ListTools(context.Background(), nil)
	require.NoError(t, err)
	require.Len(t, listResult.Tools, 2)

	names := []string{listResult.Tools[0].Name, listResult.Tools[1].Name}
	assert.Contains(t, names, "alpha__greet")
	assert.Contains(t, names, "beta__greet")
}

func TestProxy_MultipleDownstreams_ToolCallRouting(t *testing.T) {
	type EmptyInput struct{}

	session := setupProxy(t,
		downstreamSetup{
			alias: "alpha",
			setup: func(s *mcp.Server) {
				mcp.AddTool(s, &mcp.Tool{Name: "who"}, func(_ context.Context, _ *mcp.CallToolRequest, _ EmptyInput) (*mcp.CallToolResult, any, error) {
					return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "alpha"}}}, nil, nil
				})
			},
		},
		downstreamSetup{
			alias: "beta",
			setup: func(s *mcp.Server) {
				mcp.AddTool(s, &mcp.Tool{Name: "who"}, func(_ context.Context, _ *mcp.CallToolRequest, _ EmptyInput) (*mcp.CallToolResult, any, error) {
					return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "beta"}}}, nil, nil
				})
			},
		},
	)

	// Call alpha__who
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "alpha__who"})
	require.NoError(t, err)
	text := result.Content[0].(*mcp.TextContent)
	assert.Equal(t, "alpha", text.Text)

	// Call beta__who
	result, err = session.CallTool(context.Background(), &mcp.CallToolParams{Name: "beta__who"})
	require.NoError(t, err)
	text = result.Content[0].(*mcp.TextContent)
	assert.Equal(t, "beta", text.Text)
}

func TestProxy_MultipleDownstreams_ResourceList(t *testing.T) {
	session := setupProxy(t,
		downstreamSetup{
			alias: "alpha",
			setup: func(s *mcp.Server) {
				s.AddResource(&mcp.Resource{URI: "alpha://data", Name: "data"}, func(_ context.Context, _ *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
					return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: "alpha://data", Text: "alpha data"}}}, nil
				})
			},
		},
		downstreamSetup{
			alias: "beta",
			setup: func(s *mcp.Server) {
				s.AddResource(&mcp.Resource{URI: "beta://data", Name: "data"}, func(_ context.Context, _ *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
					return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: "beta://data", Text: "beta data"}}}, nil
				})
			},
		},
	)

	listResult, err := session.ListResources(context.Background(), nil)
	require.NoError(t, err)
	require.Len(t, listResult.Resources, 2)

	names := []string{listResult.Resources[0].Name, listResult.Resources[1].Name}
	assert.Contains(t, names, "alpha__data")
	assert.Contains(t, names, "beta__data")
}

func TestProxy_MultipleDownstreams_ResourceReadRouting(t *testing.T) {
	session := setupProxy(t,
		downstreamSetup{
			alias: "alpha",
			setup: func(s *mcp.Server) {
				s.AddResource(&mcp.Resource{URI: "alpha://info", Name: "info"}, func(_ context.Context, _ *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
					return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: "alpha://info", Text: "from alpha"}}}, nil
				})
			},
		},
		downstreamSetup{
			alias: "beta",
			setup: func(s *mcp.Server) {
				s.AddResource(&mcp.Resource{URI: "beta://info", Name: "info"}, func(_ context.Context, _ *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
					return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: "beta://info", Text: "from beta"}}}, nil
				})
			},
		},
	)

	result, err := session.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: "alpha://info"})
	require.NoError(t, err)
	assert.Equal(t, "from alpha", result.Contents[0].Text)

	result, err = session.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: "beta://info"})
	require.NoError(t, err)
	assert.Equal(t, "from beta", result.Contents[0].Text)
}

// setupProxyWithPolicy is like setupProxy but accepts a custom PolicyConfig.
func setupProxyWithPolicy(t *testing.T, pol config.PolicyConfig, downstreams ...downstreamSetup) *mcp.ClientSession {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	logger := slog.Default()

	cfgDownstreams := make(map[string]config.ServerConfig)
	for _, ds := range downstreams {
		cfgDownstreams[ds.alias] = config.ServerConfig{Command: "unused"}
	}

	cfg := &config.Config{
		Downstreams: cfgDownstreams,
		Policy:      pol,
		LogLevel:    "debug",
	}
	require.NoError(t, cfg.Validate())

	p := proxy.New(cfg, logger)

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

func TestProxy_PolicyAllowsToolCall(t *testing.T) {
	type EmptyInput struct{}

	session := setupProxyWithPolicy(t,
		config.PolicyConfig{
			Default: "deny",
			Rules: []config.PolicyRule{
				{Name: "allow-echo", Expression: `server == "echoserver" && tool.name == "echo"`, Effect: "allow"},
			},
		},
		downstreamSetup{
			alias: "echoserver",
			setup: func(s *mcp.Server) {
				mcp.AddTool(s, &mcp.Tool{Name: "echo"}, func(_ context.Context, _ *mcp.CallToolRequest, _ EmptyInput) (*mcp.CallToolResult, any, error) {
					return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "allowed"}}}, nil, nil
				})
			},
		},
	)

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "echoserver__echo"})
	require.NoError(t, err)
	assert.False(t, result.IsError)
	text := result.Content[0].(*mcp.TextContent)
	assert.Equal(t, "allowed", text.Text)
}

func TestProxy_PolicyDeniesToolCall(t *testing.T) {
	type EmptyInput struct{}

	session := setupProxyWithPolicy(t,
		config.PolicyConfig{
			Default: "deny",
			Rules: []config.PolicyRule{
				{Name: "allow-safe", Expression: `tool.name == "safe"`, Effect: "allow"},
			},
		},
		downstreamSetup{
			alias: "myserver",
			setup: func(s *mcp.Server) {
				mcp.AddTool(s, &mcp.Tool{Name: "danger"}, func(_ context.Context, _ *mcp.CallToolRequest, _ EmptyInput) (*mcp.CallToolResult, any, error) {
					return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "should not reach"}}}, nil, nil
				})
			},
		},
	)

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "myserver__danger"})
	require.NoError(t, err)
	assert.True(t, result.IsError)
	text := result.Content[0].(*mcp.TextContent)
	assert.Contains(t, text.Text, "denied by policy")
}

func TestProxy_PolicyDeniesResourceRead(t *testing.T) {
	session := setupProxyWithPolicy(t,
		config.PolicyConfig{
			Default: "allow",
			Rules: []config.PolicyRule{
				{Name: "block-etc", Expression: `resource.uri.startsWith("file:///etc/")`, Effect: "deny"},
			},
		},
		downstreamSetup{
			alias: "files",
			setup: func(s *mcp.Server) {
				s.AddResource(&mcp.Resource{URI: "file:///etc/passwd", Name: "passwd"}, func(_ context.Context, _ *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
					return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: "file:///etc/passwd", Text: "should not reach"}}}, nil
				})
			},
		},
	)

	_, err := session.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: "file:///etc/passwd"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "denied by policy")
}

func TestProxy_PolicyDefaultDeny_NoMatchingRule(t *testing.T) {
	type EmptyInput struct{}

	session := setupProxyWithPolicy(t,
		config.PolicyConfig{
			Default: "deny",
			Rules:   []config.PolicyRule{},
		},
		downstreamSetup{
			alias: "myserver",
			setup: func(s *mcp.Server) {
				mcp.AddTool(s, &mcp.Tool{Name: "anything"}, func(_ context.Context, _ *mcp.CallToolRequest, _ EmptyInput) (*mcp.CallToolResult, any, error) {
					return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "nope"}}}, nil, nil
				})
			},
		},
	)

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "myserver__anything"})
	require.NoError(t, err)
	assert.True(t, result.IsError)
	text := result.Content[0].(*mcp.TextContent)
	assert.Contains(t, text.Text, "denied by policy")
}

func TestProxy_NoPolicy(t *testing.T) {
	type EmptyInput struct{}

	session := setupProxyWithPolicy(t,
		config.PolicyConfig{
			Default: "allow",
		},
		downstreamSetup{
			alias: "myserver",
			setup: func(s *mcp.Server) {
				mcp.AddTool(s, &mcp.Tool{Name: "anything"}, func(_ context.Context, _ *mcp.CallToolRequest, _ EmptyInput) (*mcp.CallToolResult, any, error) {
					return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "free pass"}}}, nil, nil
				})
			},
		},
	)

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "myserver__anything"})
	require.NoError(t, err)
	assert.False(t, result.IsError)
	text := result.Content[0].(*mcp.TextContent)
	assert.Equal(t, "free pass", text.Text)
}

// setupProxyWithConfig is like setupProxy but accepts a full Config for timeout/max_output tests.
func setupProxyWithConfig(t *testing.T, cfg *config.Config, downstreams ...downstreamSetup) *mcp.ClientSession {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	logger := slog.Default()

	p := proxy.New(cfg, logger)

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

func TestProxy_ToolCallTimeout(t *testing.T) {
	type EmptyInput struct{}

	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"slow": {Command: "unused"},
		},
		Timeout: "50ms",
	}
	cfg.Policy.Default = "allow"
	require.NoError(t, cfg.Validate())

	session := setupProxyWithConfig(t, cfg,
		downstreamSetup{
			alias: "slow",
			setup: func(s *mcp.Server) {
				mcp.AddTool(s, &mcp.Tool{Name: "hang"}, func(ctx context.Context, _ *mcp.CallToolRequest, _ EmptyInput) (*mcp.CallToolResult, any, error) {
					select {
					case <-time.After(5 * time.Second):
						return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "done"}}}, nil, nil
					case <-ctx.Done():
						return nil, nil, ctx.Err()
					}
				})
			},
		},
	)

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "slow__hang"})
	require.NoError(t, err)
	assert.True(t, result.IsError)
	text := result.Content[0].(*mcp.TextContent)
	assert.Contains(t, text.Text, "timeout")
}

func TestProxy_ResourceReadTimeout(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"slow": {Command: "unused"},
		},
		Timeout: "50ms",
	}
	cfg.Policy.Default = "allow"
	require.NoError(t, cfg.Validate())

	session := setupProxyWithConfig(t, cfg,
		downstreamSetup{
			alias: "slow",
			setup: func(s *mcp.Server) {
				s.AddResource(&mcp.Resource{URI: "test://slow", Name: "slow"}, func(ctx context.Context, _ *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
					select {
					case <-time.After(5 * time.Second):
						return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: "test://slow", Text: "done"}}}, nil
					case <-ctx.Done():
						return nil, ctx.Err()
					}
				})
			},
		},
	)

	_, err := session.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: "test://slow"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timeout")
}

func TestProxy_PerDownstreamTimeout(t *testing.T) {
	type EmptyInput struct{}

	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"fast": {Command: "unused", Timeout: "50ms"},
			"slow": {Command: "unused", Timeout: "5s"},
		},
		Timeout: "5s",
	}
	cfg.Policy.Default = "allow"
	require.NoError(t, cfg.Validate())

	session := setupProxyWithConfig(t, cfg,
		downstreamSetup{
			alias: "fast",
			setup: func(s *mcp.Server) {
				mcp.AddTool(s, &mcp.Tool{Name: "hang"}, func(ctx context.Context, _ *mcp.CallToolRequest, _ EmptyInput) (*mcp.CallToolResult, any, error) {
					select {
					case <-time.After(5 * time.Second):
						return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "done"}}}, nil, nil
					case <-ctx.Done():
						return nil, nil, ctx.Err()
					}
				})
			},
		},
		downstreamSetup{
			alias: "slow",
			setup: func(s *mcp.Server) {
				mcp.AddTool(s, &mcp.Tool{Name: "quick"}, func(_ context.Context, _ *mcp.CallToolRequest, _ EmptyInput) (*mcp.CallToolResult, any, error) {
					return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ok"}}}, nil, nil
				})
			},
		},
	)

	// fast__hang should timeout (50ms timeout, handler sleeps 5s)
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "fast__hang"})
	require.NoError(t, err)
	assert.True(t, result.IsError)
	text := result.Content[0].(*mcp.TextContent)
	assert.Contains(t, text.Text, "timeout")

	// slow__quick should succeed (5s timeout, handler returns immediately)
	result, err = session.CallTool(context.Background(), &mcp.CallToolParams{Name: "slow__quick"})
	require.NoError(t, err)
	assert.False(t, result.IsError)
	text = result.Content[0].(*mcp.TextContent)
	assert.Equal(t, "ok", text.Text)
}

func TestTruncateContent_UnderLimit(t *testing.T) {
	content := []mcp.Content{&mcp.TextContent{Text: "hello"}}
	result, truncated := proxy.TruncateContent(content, 100)
	assert.False(t, truncated)
	assert.Len(t, result, 1)
	text := result[0].(*mcp.TextContent)
	assert.Equal(t, "hello", text.Text)
}

func TestTruncateContent_OverLimit(t *testing.T) {
	content := []mcp.Content{&mcp.TextContent{Text: strings.Repeat("a", 100)}}
	result, truncated := proxy.TruncateContent(content, 50)
	assert.True(t, truncated)

	// Should have original (truncated) + warning
	require.Len(t, result, 2)
	text := result[0].(*mcp.TextContent)
	assert.Len(t, text.Text, 50)
	warning := result[1].(*mcp.TextContent)
	assert.Contains(t, warning.Text, "truncated")
}

func TestTruncateContent_MultipleEntries(t *testing.T) {
	content := []mcp.Content{
		&mcp.TextContent{Text: strings.Repeat("a", 30)},
		&mcp.TextContent{Text: strings.Repeat("b", 30)},
	}
	result, truncated := proxy.TruncateContent(content, 40)
	assert.True(t, truncated)

	// First entry fits (30 bytes), second gets truncated to 10 bytes, plus warning
	require.Len(t, result, 3)
	text0 := result[0].(*mcp.TextContent)
	assert.Equal(t, strings.Repeat("a", 30), text0.Text)
	text1 := result[1].(*mcp.TextContent)
	assert.Len(t, text1.Text, 10)
	warning := result[2].(*mcp.TextContent)
	assert.Contains(t, warning.Text, "truncated")
}

func TestTruncateResourceContents_UnderLimit(t *testing.T) {
	contents := []*mcp.ResourceContents{{URI: "test://a", Text: "hello"}}
	result, truncated := proxy.TruncateResourceContents(contents, 100)
	assert.False(t, truncated)
	assert.Equal(t, "hello", result[0].Text)
}

func TestTruncateResourceContents_OverLimit(t *testing.T) {
	contents := []*mcp.ResourceContents{{URI: "test://a", Text: strings.Repeat("x", 100)}}
	result, truncated := proxy.TruncateResourceContents(contents, 50)
	assert.True(t, truncated)
	assert.Len(t, result[0].Text, 50)
	// Last entry is warning
	assert.Contains(t, result[len(result)-1].Text, "truncated")
}

func TestProxy_ToolCallTruncated(t *testing.T) {
	type EmptyInput struct{}

	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"big": {Command: "unused"},
		},
		Timeout:        "5s",
		MaxOutputBytes: 50,
	}
	cfg.Policy.Default = "allow"
	require.NoError(t, cfg.Validate())

	session := setupProxyWithConfig(t, cfg,
		downstreamSetup{
			alias: "big",
			setup: func(s *mcp.Server) {
				mcp.AddTool(s, &mcp.Tool{Name: "large"}, func(_ context.Context, _ *mcp.CallToolRequest, _ EmptyInput) (*mcp.CallToolResult, any, error) {
					return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: strings.Repeat("x", 200)}}}, nil, nil
				})
			},
		},
	)

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "big__large"})
	require.NoError(t, err)
	assert.False(t, result.IsError)
	// Should have truncated content + warning
	require.True(t, len(result.Content) >= 2)
	warning := result.Content[len(result.Content)-1].(*mcp.TextContent)
	assert.Contains(t, warning.Text, "truncated")
}

func TestProxy_ResourceReadTruncated(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"big": {Command: "unused"},
		},
		Timeout:        "5s",
		MaxOutputBytes: 50,
	}
	cfg.Policy.Default = "allow"
	require.NoError(t, cfg.Validate())

	session := setupProxyWithConfig(t, cfg,
		downstreamSetup{
			alias: "big",
			setup: func(s *mcp.Server) {
				s.AddResource(&mcp.Resource{URI: "test://big", Name: "big"}, func(_ context.Context, _ *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
					return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: "test://big", Text: strings.Repeat("y", 200)}}}, nil
				})
			},
		},
	)

	result, err := session.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: "test://big"})
	require.NoError(t, err)
	// Last content should contain truncation warning
	last := result.Contents[len(result.Contents)-1]
	assert.Contains(t, last.Text, "truncated")
}
