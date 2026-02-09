package proxy

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type explainOutput struct {
	Profile        string               `json:"profile,omitempty"`
	LocalOverride  string               `json:"local_override,omitempty"`
	Policy         explainPolicy        `json:"policy"`
	Redaction      explainRedaction      `json:"redaction,omitempty"`
	Timeout        string               `json:"timeout"`
	ApprovalTimeout string              `json:"approval_timeout"`
	MaxOutputBytes int                  `json:"max_output_bytes"`
	LogLevel       string               `json:"log_level"`
}

type explainPolicy struct {
	Default string              `json:"default"`
	Rules   []explainPolicyRule `json:"rules,omitempty"`
}

type explainPolicyRule struct {
	Name       string `json:"name"`
	Expression string `json:"expression"`
	Effect     string `json:"effect"`
	Message    string `json:"message,omitempty"`
	Source     string `json:"source,omitempty"`
}

type explainRedaction struct {
	Patterns []explainRedactionPattern `json:"patterns,omitempty"`
}

type explainRedactionPattern struct {
	Name    string `json:"name"`
	Pattern string `json:"pattern"`
	Source  string `json:"source,omitempty"`
}

func (p *Proxy) registerExplainTool() {
	p.server.AddTool(&mcp.Tool{
		Name:        "explain_effective_policy",
		Description: "Show the effective firewall policy with provenance",
		InputSchema: json.RawMessage(`{"type":"object"}`),
	}, func(_ context.Context, _ *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return p.handleExplainPolicy()
	})
}

func (p *Proxy) handleExplainPolicy() (*mcp.CallToolResult, error) {
	output := explainOutput{
		Profile:         p.profileName,
		LocalOverride:   p.localOverridePath,
		Timeout:         p.cfg.Timeout,
		ApprovalTimeout: p.cfg.ApprovalTimeout,
		MaxOutputBytes:  p.cfg.MaxOutputBytes,
		LogLevel:        p.cfg.LogLevel,
		Policy: explainPolicy{
			Default: p.cfg.Policy.Default,
		},
	}

	for _, rule := range p.cfg.Policy.Rules {
		output.Policy.Rules = append(output.Policy.Rules, explainPolicyRule{
			Name:       rule.Name,
			Expression: rule.Expression,
			Effect:     rule.Effect,
			Message:    rule.Message,
			Source:     rule.Source,
		})
	}

	for _, pat := range p.cfg.Redaction.Patterns {
		output.Redaction.Patterns = append(output.Redaction.Patterns, explainRedactionPattern{
			Name:    pat.Name,
			Pattern: pat.Pattern,
			Source:  pat.Source,
		})
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshaling policy explanation: %w", err)
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(data)}},
	}, nil
}
