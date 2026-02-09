package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os/exec"

	"github.com/VikingOwl91/mcp-firewall/internal/config"
	"github.com/VikingOwl91/mcp-firewall/internal/logging"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type Proxy struct {
	cfg        *config.Config
	logger     *slog.Logger
	server     *mcp.Server
	client     *mcp.Client
	downstream *mcp.ClientSession
}

func New(cfg *config.Config, logger *slog.Logger) *Proxy {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "mcp-firewall",
		Version: "0.1.0",
	}, &mcp.ServerOptions{
		Logger: logger,
	})

	server.AddReceivingMiddleware(logging.NewReceivingMiddleware(logger))

	client := mcp.NewClient(&mcp.Implementation{
		Name:    "mcp-firewall-client",
		Version: "0.1.0",
	}, nil)

	return &Proxy{
		cfg:    cfg,
		logger: logger,
		server: server,
		client: client,
	}
}

func (p *Proxy) ConnectDownstream(ctx context.Context, t mcp.Transport) error {
	session, err := p.client.Connect(ctx, t, nil)
	if err != nil {
		return fmt.Errorf("connecting to downstream: %w", err)
	}
	p.downstream = session
	return nil
}

func (p *Proxy) RegisterUpstreamHandlers(ctx context.Context) error {
	if err := p.registerTools(ctx); err != nil {
		return fmt.Errorf("registering tools: %w", err)
	}
	if err := p.registerResources(ctx); err != nil {
		return fmt.Errorf("registering resources: %w", err)
	}
	return nil
}

func (p *Proxy) registerTools(ctx context.Context) error {
	result, err := p.downstream.ListTools(ctx, nil)
	if err != nil {
		return err
	}

	for _, tool := range result.Tools {
		tool := tool
		p.server.AddTool(tool, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			// Forward raw arguments to downstream
			var args any
			if len(req.Params.Arguments) > 0 {
				if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
					return nil, fmt.Errorf("unmarshaling arguments: %w", err)
				}
			}

			return p.downstream.CallTool(ctx, &mcp.CallToolParams{
				Name:      req.Params.Name,
				Arguments: args,
			})
		})

		p.logger.Info("registered proxied tool", slog.String("name", tool.Name))
	}

	return nil
}

func (p *Proxy) registerResources(ctx context.Context) error {
	result, err := p.downstream.ListResources(ctx, nil)
	if err != nil {
		return err
	}

	for _, res := range result.Resources {
		res := res
		p.server.AddResource(res, func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			return p.downstream.ReadResource(ctx, &mcp.ReadResourceParams{
				URI: req.Params.URI,
			})
		})

		p.logger.Info("registered proxied resource", slog.String("uri", res.URI))
	}

	return nil
}

func (p *Proxy) ServeUpstream(ctx context.Context, t mcp.Transport) error {
	return p.server.Run(ctx, t)
}

func (p *Proxy) Run(ctx context.Context, upstream mcp.Transport) error {
	cmd := exec.CommandContext(ctx, p.cfg.Downstream.Command, p.cfg.Downstream.Args...)
	cmd.Env = append(cmd.Environ(), p.cfg.Downstream.Env...)

	dsTransport := &mcp.CommandTransport{Command: cmd}

	if err := p.ConnectDownstream(ctx, dsTransport); err != nil {
		return err
	}
	defer p.downstream.Close()

	if err := p.RegisterUpstreamHandlers(ctx); err != nil {
		return err
	}

	p.logger.Info("proxy ready, serving upstream")
	return p.ServeUpstream(ctx, upstream)
}
