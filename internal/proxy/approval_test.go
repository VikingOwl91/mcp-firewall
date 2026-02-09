package proxy_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/VikingOwl91/mcp-firewall/internal/proxy"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupElicitationTest creates a server+client pair where the tool handler calls
// RequestApprovalForTest. The elicitHandler controls what the client responds.
func setupElicitationTest(t *testing.T, elicitHandler func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error)) *mcp.ClientSession {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	server := mcp.NewServer(&mcp.Implementation{Name: "test-server", Version: "0.1.0"}, nil)

	server.AddTool(&mcp.Tool{
		Name:        "approval-test",
		InputSchema: json.RawMessage(`{"type":"object"}`),
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		action, err := proxy.RequestApprovalForTest(ctx, req.Session, "test-rule", "Test approval message", 5*time.Second)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("action=%s err=%s", action, err.Error())}},
				IsError: true,
			}, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("action=%s", action)}},
		}, nil
	})

	srvT, clientT := mcp.NewInMemoryTransports()
	_, err := server.Connect(ctx, srvT, nil)
	require.NoError(t, err)

	clientOpts := &mcp.ClientOptions{}
	if elicitHandler != nil {
		clientOpts.ElicitationHandler = elicitHandler
	}

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0.1.0"}, clientOpts)
	session, err := client.Connect(ctx, clientT, nil)
	require.NoError(t, err)
	t.Cleanup(func() { session.Close() })

	return session
}

func TestRequestApproval_Accepted(t *testing.T) {
	session := setupElicitationTest(t, func(_ context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		return &mcp.ElicitResult{Action: "accept"}, nil
	})

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "approval-test"})
	require.NoError(t, err)
	assert.False(t, result.IsError)
	text := result.Content[0].(*mcp.TextContent)
	assert.Equal(t, "action=accept", text.Text)
}

func TestRequestApproval_Declined(t *testing.T) {
	session := setupElicitationTest(t, func(_ context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		return &mcp.ElicitResult{Action: "decline"}, nil
	})

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "approval-test"})
	require.NoError(t, err)
	assert.True(t, result.IsError)
	text := result.Content[0].(*mcp.TextContent)
	assert.Contains(t, text.Text, "action=decline")
	assert.Contains(t, text.Text, "declined")
}

func TestRequestApproval_Cancelled(t *testing.T) {
	session := setupElicitationTest(t, func(_ context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		return &mcp.ElicitResult{Action: "cancel"}, nil
	})

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "approval-test"})
	require.NoError(t, err)
	assert.True(t, result.IsError)
	text := result.Content[0].(*mcp.TextContent)
	assert.Contains(t, text.Text, "action=cancel")
	assert.Contains(t, text.Text, "cancelled")
}

func TestRequestApproval_NoElicitationSupport(t *testing.T) {
	session := setupElicitationTest(t, nil)

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "approval-test"})
	require.NoError(t, err)
	assert.True(t, result.IsError)
	text := result.Content[0].(*mcp.TextContent)
	assert.Contains(t, text.Text, "action=unsupported")
	assert.Contains(t, text.Text, "requires user approval")
}

func TestRequestApproval_CustomMessage(t *testing.T) {
	var receivedMessage string
	session := setupElicitationTest(t, func(_ context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		receivedMessage = req.Params.Message
		return &mcp.ElicitResult{Action: "accept"}, nil
	})

	_, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "approval-test"})
	require.NoError(t, err)
	assert.Equal(t, "Test approval message", receivedMessage)
}

func TestRequestApproval_Timeout(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	server := mcp.NewServer(&mcp.Implementation{Name: "test-server", Version: "0.1.0"}, nil)

	server.AddTool(&mcp.Tool{
		Name:        "approval-timeout",
		InputSchema: json.RawMessage(`{"type":"object"}`),
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// Use a very short timeout
		action, err := proxy.RequestApprovalForTest(ctx, req.Session, "test-rule", "", 10*time.Millisecond)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("action=%s err=%s", action, err.Error())}},
				IsError: true,
			}, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("action=%s", action)}},
		}, nil
	})

	srvT, clientT := mcp.NewInMemoryTransports()
	_, err := server.Connect(ctx, srvT, nil)
	require.NoError(t, err)

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0.1.0"}, &mcp.ClientOptions{
		ElicitationHandler: func(ctx context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
			// Simulate slow user response
			select {
			case <-time.After(5 * time.Second):
				return &mcp.ElicitResult{Action: "accept"}, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		},
	})
	session, err := client.Connect(ctx, clientT, nil)
	require.NoError(t, err)
	t.Cleanup(func() { session.Close() })

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "approval-timeout"})
	require.NoError(t, err)
	assert.True(t, result.IsError)
	text := result.Content[0].(*mcp.TextContent)
	assert.Contains(t, text.Text, "timeout")
}
