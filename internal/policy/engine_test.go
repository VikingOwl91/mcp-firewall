package policy_test

import (
	"testing"

	"github.com/VikingOwl91/mcp-firewall/internal/config"
	"github.com/VikingOwl91/mcp-firewall/internal/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew_ValidRules(t *testing.T) {
	cfg := config.PolicyConfig{
		Default: "deny",
		Rules: []config.PolicyRule{
			{Name: "allow-echo", Expression: `server == "echoserver"`, Effect: "allow"},
		},
	}
	e, err := policy.New(cfg)
	require.NoError(t, err)
	assert.NotNil(t, e)
}

func TestNew_InvalidExpression(t *testing.T) {
	cfg := config.PolicyConfig{
		Default: "deny",
		Rules: []config.PolicyRule{
			{Name: "bad", Expression: `this is not valid CEL !!!`, Effect: "allow"},
		},
	}
	_, err := policy.New(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bad")
}

func TestEvaluate_AllowByRule(t *testing.T) {
	cfg := config.PolicyConfig{
		Default: "deny",
		Rules: []config.PolicyRule{
			{Name: "allow-echo", Expression: `server == "echoserver" && tool.name == "echo"`, Effect: "allow"},
		},
	}
	e, err := policy.New(cfg)
	require.NoError(t, err)

	d := e.Evaluate(policy.RequestContext{
		Method: "tools/call",
		Server: "echoserver",
		Tool:   policy.ToolContext{Name: "echo"},
	})
	assert.Equal(t, policy.Allow, d.Effect)
	assert.Equal(t, "allow-echo", d.Rule)
	assert.Empty(t, d.Message)
}

func TestEvaluate_DenyByRule(t *testing.T) {
	cfg := config.PolicyConfig{
		Default: "allow",
		Rules: []config.PolicyRule{
			{Name: "block-danger", Expression: `tool.name == "danger"`, Effect: "deny"},
		},
	}
	e, err := policy.New(cfg)
	require.NoError(t, err)

	d := e.Evaluate(policy.RequestContext{
		Method: "tools/call",
		Server: "myserver",
		Tool:   policy.ToolContext{Name: "danger"},
	})
	assert.Equal(t, policy.Deny, d.Effect)
	assert.Equal(t, "block-danger", d.Rule)
}

func TestEvaluate_DefaultDeny(t *testing.T) {
	cfg := config.PolicyConfig{
		Default: "deny",
		Rules: []config.PolicyRule{
			{Name: "allow-specific", Expression: `tool.name == "safe"`, Effect: "allow"},
		},
	}
	e, err := policy.New(cfg)
	require.NoError(t, err)

	d := e.Evaluate(policy.RequestContext{
		Method: "tools/call",
		Server: "myserver",
		Tool:   policy.ToolContext{Name: "other"},
	})
	assert.Equal(t, policy.Deny, d.Effect)
	assert.Equal(t, "default:deny", d.Rule)
}

func TestEvaluate_DefaultAllow(t *testing.T) {
	cfg := config.PolicyConfig{
		Default: "allow",
		Rules:   []config.PolicyRule{},
	}
	e, err := policy.New(cfg)
	require.NoError(t, err)

	d := e.Evaluate(policy.RequestContext{
		Method: "tools/call",
		Server: "myserver",
		Tool:   policy.ToolContext{Name: "anything"},
	})
	assert.Equal(t, policy.Allow, d.Effect)
	assert.Equal(t, "default:allow", d.Rule)
}

func TestEvaluate_FirstMatchWins(t *testing.T) {
	cfg := config.PolicyConfig{
		Default: "deny",
		Rules: []config.PolicyRule{
			{Name: "deny-all", Expression: `true`, Effect: "deny"},
			{Name: "allow-all", Expression: `true`, Effect: "allow"},
		},
	}
	e, err := policy.New(cfg)
	require.NoError(t, err)

	d := e.Evaluate(policy.RequestContext{
		Method: "tools/call",
		Server: "myserver",
		Tool:   policy.ToolContext{Name: "test"},
	})
	assert.Equal(t, policy.Deny, d.Effect)
	assert.Equal(t, "deny-all", d.Rule)
}

func TestEvaluate_ToolArguments(t *testing.T) {
	cfg := config.PolicyConfig{
		Default: "deny",
		Rules: []config.PolicyRule{
			{Name: "allow-safe-args", Expression: `tool.arguments["mode"] == "safe"`, Effect: "allow"},
		},
	}
	e, err := policy.New(cfg)
	require.NoError(t, err)

	d := e.Evaluate(policy.RequestContext{
		Method: "tools/call",
		Server: "myserver",
		Tool: policy.ToolContext{
			Name:      "run",
			Arguments: map[string]any{"mode": "safe"},
		},
	})
	assert.Equal(t, policy.Allow, d.Effect)
	assert.Equal(t, "allow-safe-args", d.Rule)
}

func TestEvaluate_ResourceURI(t *testing.T) {
	cfg := config.PolicyConfig{
		Default: "allow",
		Rules: []config.PolicyRule{
			{Name: "block-etc", Expression: `resource.uri.startsWith("file:///etc/")`, Effect: "deny"},
		},
	}
	e, err := policy.New(cfg)
	require.NoError(t, err)

	d := e.Evaluate(policy.RequestContext{
		Method:   "resources/read",
		Server:   "files",
		Resource: policy.ResourceContext{URI: "file:///etc/passwd"},
	})
	assert.Equal(t, policy.Deny, d.Effect)
	assert.Equal(t, "block-etc", d.Rule)

	d = e.Evaluate(policy.RequestContext{
		Method:   "resources/read",
		Server:   "files",
		Resource: policy.ResourceContext{URI: "file:///home/user/data"},
	})
	assert.Equal(t, policy.Allow, d.Effect)
	assert.Equal(t, "default:allow", d.Rule)
}

func TestEvaluate_FailClosed(t *testing.T) {
	// A rule that evaluates to a non-boolean should fail closed (deny)
	cfg := config.PolicyConfig{
		Default: "allow",
		Rules: []config.PolicyRule{
			{Name: "bad-rule", Expression: `"not a bool"`, Effect: "allow"},
		},
	}
	e, err := policy.New(cfg)
	require.NoError(t, err)

	d := e.Evaluate(policy.RequestContext{
		Method: "tools/call",
		Server: "myserver",
		Tool:   policy.ToolContext{Name: "test"},
	})
	assert.Equal(t, policy.Deny, d.Effect)
	assert.Contains(t, d.Rule, "error")
}

func TestEvaluate_MethodMatching(t *testing.T) {
	cfg := config.PolicyConfig{
		Default: "deny",
		Rules: []config.PolicyRule{
			{Name: "allow-list", Expression: `method == "tools/list"`, Effect: "allow"},
		},
	}
	e, err := policy.New(cfg)
	require.NoError(t, err)

	d := e.Evaluate(policy.RequestContext{
		Method: "tools/list",
		Server: "myserver",
	})
	assert.Equal(t, policy.Allow, d.Effect)

	d = e.Evaluate(policy.RequestContext{
		Method: "tools/call",
		Server: "myserver",
	})
	assert.Equal(t, policy.Deny, d.Effect)
}

func TestNew_PromptEffectRule(t *testing.T) {
	cfg := config.PolicyConfig{
		Default: "deny",
		Rules: []config.PolicyRule{
			{Name: "ask-first", Expression: `tool.name == "danger"`, Effect: "prompt"},
		},
	}
	e, err := policy.New(cfg)
	require.NoError(t, err)
	assert.NotNil(t, e)
}

func TestEvaluate_PromptByRule(t *testing.T) {
	cfg := config.PolicyConfig{
		Default: "deny",
		Rules: []config.PolicyRule{
			{Name: "ask-first", Expression: `tool.name == "danger"`, Effect: "prompt"},
		},
	}
	e, err := policy.New(cfg)
	require.NoError(t, err)

	d := e.Evaluate(policy.RequestContext{
		Method: "tools/call",
		Server: "myserver",
		Tool:   policy.ToolContext{Name: "danger"},
	})
	assert.Equal(t, policy.Prompt, d.Effect)
	assert.Equal(t, "ask-first", d.Rule)
	assert.Empty(t, d.Message)
}

func TestEvaluate_PromptWithMessage(t *testing.T) {
	cfg := config.PolicyConfig{
		Default: "deny",
		Rules: []config.PolicyRule{
			{Name: "ask-first", Expression: `tool.name == "danger"`, Effect: "prompt", Message: "This tool modifies production data"},
		},
	}
	e, err := policy.New(cfg)
	require.NoError(t, err)

	d := e.Evaluate(policy.RequestContext{
		Method: "tools/call",
		Server: "myserver",
		Tool:   policy.ToolContext{Name: "danger"},
	})
	assert.Equal(t, policy.Prompt, d.Effect)
	assert.Equal(t, "ask-first", d.Rule)
	assert.Equal(t, "This tool modifies production data", d.Message)
}

func TestEvaluate_FirstMatchWins_Prompt(t *testing.T) {
	cfg := config.PolicyConfig{
		Default: "deny",
		Rules: []config.PolicyRule{
			{Name: "prompt-all", Expression: `true`, Effect: "prompt"},
			{Name: "allow-all", Expression: `true`, Effect: "allow"},
		},
	}
	e, err := policy.New(cfg)
	require.NoError(t, err)

	d := e.Evaluate(policy.RequestContext{
		Method: "tools/call",
		Server: "myserver",
		Tool:   policy.ToolContext{Name: "test"},
	})
	assert.Equal(t, policy.Prompt, d.Effect)
	assert.Equal(t, "prompt-all", d.Rule)
}

func TestEvaluate_HasMacro_KeyExists(t *testing.T) {
	cfg := config.PolicyConfig{
		Default: "deny",
		Rules: []config.PolicyRule{
			{Name: "allow-workspace", Expression: `has(tool.arguments.path) && tool.arguments.path.startsWith("/workspace/")`, Effect: "allow"},
		},
	}
	e, err := policy.New(cfg)
	require.NoError(t, err)

	d := e.Evaluate(policy.RequestContext{
		Method: "tools/call",
		Server: "files",
		Tool: policy.ToolContext{
			Name:      "read",
			Arguments: map[string]any{"path": "/workspace/src/main.go"},
		},
	})
	assert.Equal(t, policy.Allow, d.Effect)
	assert.Equal(t, "allow-workspace", d.Rule)
}

func TestEvaluate_HasMacro_KeyMissing(t *testing.T) {
	cfg := config.PolicyConfig{
		Default: "deny",
		Rules: []config.PolicyRule{
			{Name: "allow-workspace", Expression: `has(tool.arguments.path) && tool.arguments.path.startsWith("/workspace/")`, Effect: "allow"},
		},
	}
	e, err := policy.New(cfg)
	require.NoError(t, err)

	// Missing "path" key — has() returns false, rule doesn't match, falls to default
	d := e.Evaluate(policy.RequestContext{
		Method: "tools/call",
		Server: "files",
		Tool: policy.ToolContext{
			Name:      "read",
			Arguments: map[string]any{"other": "value"},
		},
	})
	assert.Equal(t, policy.Deny, d.Effect)
	assert.Equal(t, "default:deny", d.Rule)
}

func TestEvaluate_MissingKeyWithoutHas_FailsClosed(t *testing.T) {
	cfg := config.PolicyConfig{
		Default: "allow",
		Rules: []config.PolicyRule{
			{Name: "check-path", Expression: `tool.arguments.path == "/foo"`, Effect: "allow"},
		},
	}
	e, err := policy.New(cfg)
	require.NoError(t, err)

	// Missing key without has() guard — CEL error → Deny
	d := e.Evaluate(policy.RequestContext{
		Method: "tools/call",
		Server: "files",
		Tool: policy.ToolContext{
			Name:      "read",
			Arguments: map[string]any{},
		},
	})
	assert.Equal(t, policy.Deny, d.Effect)
	assert.Contains(t, d.Rule, "error")
}

func TestEvaluate_ArgumentsStartsWith(t *testing.T) {
	cfg := config.PolicyConfig{
		Default: "deny",
		Rules: []config.PolicyRule{
			{Name: "allow-home", Expression: `has(tool.arguments.path) && tool.arguments.path.startsWith("/home/user/")`, Effect: "allow"},
		},
	}
	e, err := policy.New(cfg)
	require.NoError(t, err)

	d := e.Evaluate(policy.RequestContext{
		Method: "tools/call",
		Server: "files",
		Tool: policy.ToolContext{
			Name:      "read",
			Arguments: map[string]any{"path": "/home/user/docs/file.txt"},
		},
	})
	assert.Equal(t, policy.Allow, d.Effect)

	d = e.Evaluate(policy.RequestContext{
		Method: "tools/call",
		Server: "files",
		Tool: policy.ToolContext{
			Name:      "read",
			Arguments: map[string]any{"path": "/etc/passwd"},
		},
	})
	assert.Equal(t, policy.Deny, d.Effect)
}

func TestEvaluate_ArgumentsMatches(t *testing.T) {
	cfg := config.PolicyConfig{
		Default: "deny",
		Rules: []config.PolicyRule{
			{Name: "allow-safe-cmd", Expression: `has(tool.arguments.command) && tool.arguments.command.matches("^(ls|cat|echo)$")`, Effect: "allow"},
		},
	}
	e, err := policy.New(cfg)
	require.NoError(t, err)

	d := e.Evaluate(policy.RequestContext{
		Method: "tools/call",
		Server: "shell",
		Tool: policy.ToolContext{
			Name:      "exec",
			Arguments: map[string]any{"command": "ls"},
		},
	})
	assert.Equal(t, policy.Allow, d.Effect)

	d = e.Evaluate(policy.RequestContext{
		Method: "tools/call",
		Server: "shell",
		Tool: policy.ToolContext{
			Name:      "exec",
			Arguments: map[string]any{"command": "rm -rf /"},
		},
	})
	assert.Equal(t, policy.Deny, d.Effect)
}
