package proxy

import (
	"context"
	"fmt"
	"time"

	"github.com/VikingOwl91/mcp-firewall/internal/policy"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// RequestApprovalForTest exposes requestApproval for unit tests.
func RequestApprovalForTest(ctx context.Context, session *mcp.ServerSession, rule, message string, timeout time.Duration) (string, error) {
	return requestApproval(ctx, session, policy.Decision{Rule: rule, Message: message}, timeout)
}

func requestApproval(ctx context.Context, session *mcp.ServerSession, decision policy.Decision, timeout time.Duration) (string, error) {
	if session.InitializeParams().Capabilities.Elicitation == nil {
		msg := fmt.Sprintf("action requires user approval: %s", decision.Rule)
		if decision.Message != "" {
			msg = fmt.Sprintf("action requires user approval: %s", decision.Message)
		}
		return "unsupported", fmt.Errorf("%s", msg)
	}

	message := fmt.Sprintf("Policy rule %q requires approval.", decision.Rule)
	if decision.Message != "" {
		message = decision.Message
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	result, err := session.Elicit(timeoutCtx, &mcp.ElicitParams{
		Message: message,
	})
	if err != nil {
		if ctx.Err() != nil || timeoutCtx.Err() != nil {
			return "timeout", fmt.Errorf("approval timed out after %s", timeout)
		}
		return "error", fmt.Errorf("elicitation failed: %w", err)
	}

	switch result.Action {
	case "accept":
		return "accept", nil
	case "decline":
		return "decline", fmt.Errorf("user declined: %s", decision.Rule)
	default:
		return result.Action, fmt.Errorf("user cancelled approval: %s", decision.Rule)
	}
}
