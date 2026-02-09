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

	mw := logging.NewReceivingMiddleware(logger)

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

	mw := logging.NewReceivingMiddleware(logger)

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
