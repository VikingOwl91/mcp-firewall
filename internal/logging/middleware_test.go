package logging_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"

	"github.com/VikingOwl91/mcp-firewall/internal/logging"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMiddleware_LogsMethodAndDuration(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	mw := logging.NewReceivingMiddleware(logger, nil)

	handler := mw(func(_ context.Context, method string, req mcp.Request) (mcp.Result, error) {
		return nil, nil
	})

	_, err := handler(context.Background(), "tools/list", nil)
	require.NoError(t, err)

	var entry map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &entry))

	assert.Equal(t, "tools/list", entry["method"])
	assert.Equal(t, "request", entry["direction"])
	assert.Contains(t, entry, "duration_ms")
	assert.Equal(t, false, entry["error"])
}

func TestMiddleware_LogsError(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	mw := logging.NewReceivingMiddleware(logger, nil)

	handler := mw(func(_ context.Context, method string, req mcp.Request) (mcp.Result, error) {
		return nil, errors.New("boom")
	})

	_, err := handler(context.Background(), "tools/call", nil)
	require.Error(t, err)

	var entry map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &entry))

	assert.Equal(t, "tools/call", entry["method"])
	assert.Equal(t, true, entry["error"])
}

func TestWithAuditInfo_RoundTrip(t *testing.T) {
	info := &logging.AuditInfo{
		Server:       "echoserver",
		ToolName:     "echo",
		PolicyEffect: "allow",
		PolicyRule:   "allow-echo",
	}

	ctx := logging.WithAuditInfo(context.Background(), info)
	got := logging.GetAuditInfo(ctx)
	require.NotNil(t, got)
	assert.Equal(t, "echoserver", got.Server)
	assert.Equal(t, "echo", got.ToolName)
	assert.Equal(t, "allow", got.PolicyEffect)
	assert.Equal(t, "allow-echo", got.PolicyRule)
}

func TestGetAuditInfo_Empty(t *testing.T) {
	got := logging.GetAuditInfo(context.Background())
	assert.Nil(t, got)
}

func TestMiddleware_AuditInfo_ToolCall(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	mw := logging.NewReceivingMiddleware(logger, nil)

	handler := mw(func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		if info := logging.GetAuditInfo(ctx); info != nil {
			info.Server = "echoserver"
			info.ToolName = "echo"
			info.PolicyEffect = "allow"
			info.PolicyRule = "allow-echo"
		}
		return nil, nil
	})

	_, err := handler(context.Background(), "tools/call", nil)
	require.NoError(t, err)

	var entry map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &entry))

	assert.Equal(t, "tools/call", entry["method"])
	assert.Equal(t, "echoserver", entry["server"])
	assert.Equal(t, "echo", entry["tool"])
	assert.Equal(t, "allow", entry["policy_effect"])
	assert.Equal(t, "allow-echo", entry["policy_rule"])
}

func TestMiddleware_AuditInfo_PolicyDenied(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	mw := logging.NewReceivingMiddleware(logger, nil)

	handler := mw(func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		if info := logging.GetAuditInfo(ctx); info != nil {
			info.Server = "myserver"
			info.ToolName = "danger"
			info.PolicyEffect = "deny"
			info.PolicyRule = "default:deny"
		}
		return nil, nil
	})

	_, err := handler(context.Background(), "tools/call", nil)
	require.NoError(t, err)

	var entry map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &entry))

	assert.Equal(t, "deny", entry["policy_effect"])
	assert.Equal(t, "default:deny", entry["policy_rule"])
	assert.Equal(t, "danger", entry["tool"])
}

func TestMiddleware_ApprovalActionLogged(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	mw := logging.NewReceivingMiddleware(logger, nil)

	handler := mw(func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		if info := logging.GetAuditInfo(ctx); info != nil {
			info.Server = "myserver"
			info.ToolName = "danger"
			info.PolicyEffect = "prompt"
			info.PolicyRule = "ask-first"
			info.ApprovalAction = "accept"
		}
		return nil, nil
	})

	_, err := handler(context.Background(), "tools/call", nil)
	require.NoError(t, err)

	var entry map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &entry))

	assert.Equal(t, "accept", entry["approval_action"])
	assert.Equal(t, "prompt", entry["policy_effect"])
}

func TestMiddleware_AuditInfo_Empty(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	mw := logging.NewReceivingMiddleware(logger, nil)

	handler := mw(func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		// Handler doesn't set AuditInfo fields
		return nil, nil
	})

	_, err := handler(context.Background(), "tools/list", nil)
	require.NoError(t, err)

	var entry map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &entry))

	assert.Equal(t, "tools/list", entry["method"])
	// No audit fields should be present
	assert.NotContains(t, entry, "server")
	assert.NotContains(t, entry, "tool")
	assert.NotContains(t, entry, "policy_effect")
	// No hash chain fields when nil
	assert.NotContains(t, entry, "audit_seq")
	assert.NotContains(t, entry, "entry_hash")
	assert.NotContains(t, entry, "prev_hash")
}

func TestMiddleware_HashChainFields(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	hc := logging.NewHashChain()

	mw := logging.NewReceivingMiddleware(logger, hc)

	handler := mw(func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		if info := logging.GetAuditInfo(ctx); info != nil {
			info.Server = "echoserver"
			info.ToolName = "echo"
		}
		return nil, nil
	})

	_, err := handler(context.Background(), "tools/call", nil)
	require.NoError(t, err)

	var entry map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &entry))

	assert.Equal(t, float64(1), entry["audit_seq"])
	assert.NotEmpty(t, entry["entry_hash"])
	assert.NotEmpty(t, entry["prev_hash"])
}

func TestMiddleware_HashChainSequential(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	hc := logging.NewHashChain()

	mw := logging.NewReceivingMiddleware(logger, hc)

	handler := mw(func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		return nil, nil
	})

	// First request
	_, err := handler(context.Background(), "tools/list", nil)
	require.NoError(t, err)

	lines := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
	require.Len(t, lines, 1)
	var entry1 map[string]any
	require.NoError(t, json.Unmarshal(lines[0], &entry1))
	assert.Equal(t, float64(1), entry1["audit_seq"])

	// Second request
	_, err = handler(context.Background(), "tools/call", nil)
	require.NoError(t, err)

	lines = bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
	require.Len(t, lines, 2)
	var entry2 map[string]any
	require.NoError(t, json.Unmarshal(lines[1], &entry2))
	assert.Equal(t, float64(2), entry2["audit_seq"])

	// Chain links: entry2's prev_hash == entry1's entry_hash
	assert.Equal(t, entry1["entry_hash"], entry2["prev_hash"])
}
