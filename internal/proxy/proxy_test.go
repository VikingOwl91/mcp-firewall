package proxy_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"testing"

	"github.com/VikingOwl91/mcp-firewall/internal/config"
	"github.com/VikingOwl91/mcp-firewall/internal/proxy"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupProxy creates a downstream MCP server, connects a proxy to it via
// in-memory transports, and returns a client session talking to the proxy's
// upstream side. The caller must cancel the returned context to tear everything down.
func setupProxy(t *testing.T, setupDownstream func(s *mcp.Server)) *mcp.ClientSession {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	logger := slog.Default()
	cfg := &config.Config{
		Downstream: config.ServerConfig{Command: "unused"},
		LogLevel:   "debug",
	}

	// --- downstream server ---
	downstream := mcp.NewServer(&mcp.Implementation{
		Name: "test-downstream", Version: "0.1.0",
	}, nil)
	setupDownstream(downstream)

	dsServerT, dsClientT := mcp.NewInMemoryTransports()

	// Start downstream server (non-blocking Connect)
	_, err := downstream.Connect(ctx, dsServerT, nil)
	require.NoError(t, err)

	// --- proxy ---
	p := proxy.New(cfg, logger)

	err = p.ConnectDownstream(ctx, dsClientT)
	require.NoError(t, err)

	err = p.RegisterUpstreamHandlers(ctx)
	require.NoError(t, err)

	// --- upstream client connects to proxy ---
	upServerT, upClientT := mcp.NewInMemoryTransports()

	// Serve upstream in background
	go func() {
		_ = p.ServeUpstream(ctx, upServerT)
	}()

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

	session := setupProxy(t, func(s *mcp.Server) {
		mcp.AddTool(s, &mcp.Tool{
			Name:        "echo",
			Description: "echoes a message",
		}, func(_ context.Context, req *mcp.CallToolRequest, input EchoInput) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("echo: %s", input.Message)}},
			}, nil, nil
		})
	})

	// List tools
	listResult, err := session.ListTools(context.Background(), nil)
	require.NoError(t, err)
	require.Len(t, listResult.Tools, 1)
	assert.Equal(t, "echo", listResult.Tools[0].Name)
	assert.Equal(t, "echoes a message", listResult.Tools[0].Description)

	// Call tool
	callResult, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "echo",
		Arguments: map[string]any{"message": "hello"},
	})
	require.NoError(t, err)
	require.Len(t, callResult.Content, 1)

	text, ok := callResult.Content[0].(*mcp.TextContent)
	require.True(t, ok, "expected TextContent, got %T", callResult.Content[0])
	assert.Equal(t, "echo: hello", text.Text)
}

func TestProxy_ResourceListAndRead(t *testing.T) {
	session := setupProxy(t, func(s *mcp.Server) {
		s.AddResource(&mcp.Resource{
			URI:  "test://hello",
			Name: "hello",
		}, func(_ context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			return &mcp.ReadResourceResult{
				Contents: []*mcp.ResourceContents{{URI: req.Params.URI, Text: "Hello!"}},
			}, nil
		})
	})

	// List resources
	listResult, err := session.ListResources(context.Background(), nil)
	require.NoError(t, err)
	require.Len(t, listResult.Resources, 1)
	assert.Equal(t, "test://hello", listResult.Resources[0].URI)
	assert.Equal(t, "hello", listResult.Resources[0].Name)

	// Read resource
	readResult, err := session.ReadResource(context.Background(), &mcp.ReadResourceParams{
		URI: "test://hello",
	})
	require.NoError(t, err)
	require.Len(t, readResult.Contents, 1)
	assert.Equal(t, "Hello!", readResult.Contents[0].Text)
}

func TestProxy_NoToolsNoResources(t *testing.T) {
	session := setupProxy(t, func(s *mcp.Server) {
		// No tools, no resources
	})

	listTools, err := session.ListTools(context.Background(), nil)
	require.NoError(t, err)
	assert.Empty(t, listTools.Tools)

	listRes, err := session.ListResources(context.Background(), nil)
	require.NoError(t, err)
	assert.Empty(t, listRes.Resources)
}

func TestProxy_DownstreamError(t *testing.T) {
	session := setupProxy(t, func(s *mcp.Server) {
		s.AddTool(&mcp.Tool{
			Name:        "fail",
			InputSchema: json.RawMessage(`{"type":"object"}`),
		}, func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: "something went wrong"}},
				IsError: true,
			}, nil
		})
	})

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "fail",
	})
	require.NoError(t, err) // transport-level should succeed
	assert.True(t, result.IsError)
	text := result.Content[0].(*mcp.TextContent)
	assert.Equal(t, "something went wrong", text.Text)
}

func TestProxy_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	logger := slog.Default()
	cfg := &config.Config{
		Downstream: config.ServerConfig{Command: "unused"},
		LogLevel:   "debug",
	}

	downstream := mcp.NewServer(&mcp.Implementation{
		Name: "test-downstream", Version: "0.1.0",
	}, nil)

	dsServerT, dsClientT := mcp.NewInMemoryTransports()
	_, err := downstream.Connect(ctx, dsServerT, nil)
	require.NoError(t, err)

	p := proxy.New(cfg, logger)
	err = p.ConnectDownstream(ctx, dsClientT)
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
	// Should return without hanging; error may be nil or context-related
	if err != nil {
		assert.ErrorIs(t, err, context.Canceled)
	}
}
