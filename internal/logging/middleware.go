package logging

import (
	"context"
	"log/slog"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func NewReceivingMiddleware(logger *slog.Logger) mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			start := time.Now()
			result, err := next(ctx, method, req)
			duration := time.Since(start)

			logger.InfoContext(ctx, "mcp request",
				slog.String("method", method),
				slog.String("direction", "request"),
				slog.Float64("duration_ms", float64(duration.Microseconds())/1000.0),
				slog.Bool("error", err != nil),
			)

			return result, err
		}
	}
}
