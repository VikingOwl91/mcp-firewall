package main

import (
	"context"
	"fmt"
	"log"
	"os/signal"
	"syscall"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type EchoInput struct {
	Message string `json:"message"`
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	server := mcp.NewServer(&mcp.Implementation{
		Name:    "echoserver",
		Version: "0.1.0",
	}, nil)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "echo",
		Description: "Echoes back the given message",
	}, func(_ context.Context, req *mcp.CallToolRequest, input EchoInput) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("echo: %s", input.Message)}},
		}, nil, nil
	})

	server.AddResource(&mcp.Resource{
		URI:  "test://hello",
		Name: "hello",
	}, func(_ context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		return &mcp.ReadResourceResult{
			Contents: []*mcp.ResourceContents{{URI: req.Params.URI, Text: "Hello from echo server!"}},
		}, nil
	})

	if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
