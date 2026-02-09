package config_test

import (
	"testing"

	"github.com/VikingOwl91/mcp-firewall/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func baseConfig() *config.Config {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo"},
		},
		Policy: config.PolicyConfig{
			Default: "deny",
			Rules: []config.PolicyRule{
				{Name: "allow-echo", Expression: `tool.name == "echo"`, Effect: "allow", Source: "base"},
			},
		},
		Redaction: config.RedactionConfig{
			Patterns: []config.RedactionPattern{
				{Name: "api-key", Pattern: `sk-[a-zA-Z0-9]{32}`, Source: "base"},
			},
		},
		Timeout:         "60s",
		ApprovalTimeout: "2m",
		MaxOutputBytes:  1048576,
		LogLevel:        "info",
	}
	return cfg
}

func TestMergeLocal_NilLocalNoOp(t *testing.T) {
	base := baseConfig()

	result, err := config.MergeLocal(base, nil, false)
	require.NoError(t, err)
	assert.Equal(t, base.Policy.Default, result.Policy.Default)
	assert.Equal(t, len(base.Policy.Rules), len(result.Policy.Rules))
	assert.Equal(t, base.Timeout, result.Timeout)
	// Should be a copy, not the same pointer
	assert.NotSame(t, base, result)
}

func TestMergeLocal_DenyRulesPrepended(t *testing.T) {
	base := baseConfig()
	local := &config.LocalOverride{
		Policy: &config.PolicyConfig{
			Rules: []config.PolicyRule{
				{Name: "block-rm", Expression: `tool.name == "rm"`, Effect: "deny"},
			},
		},
	}

	result, err := config.MergeLocal(base, local, false)
	require.NoError(t, err)
	require.Len(t, result.Policy.Rules, 2)
	// Local deny rule comes first
	assert.Equal(t, "block-rm", result.Policy.Rules[0].Name)
	assert.Equal(t, "local", result.Policy.Rules[0].Source)
	// Base rule comes after
	assert.Equal(t, "allow-echo", result.Policy.Rules[1].Name)
}

func TestMergeLocal_PromptRulesPrepended(t *testing.T) {
	base := baseConfig()
	local := &config.LocalOverride{
		Policy: &config.PolicyConfig{
			Rules: []config.PolicyRule{
				{Name: "prompt-deploy", Expression: `tool.name == "deploy"`, Effect: "prompt"},
			},
		},
	}

	result, err := config.MergeLocal(base, local, false)
	require.NoError(t, err)
	require.Len(t, result.Policy.Rules, 2)
	assert.Equal(t, "prompt-deploy", result.Policy.Rules[0].Name)
	assert.Equal(t, "local", result.Policy.Rules[0].Source)
}

func TestMergeLocal_AllowRulesRejected(t *testing.T) {
	base := baseConfig()
	local := &config.LocalOverride{
		Policy: &config.PolicyConfig{
			Rules: []config.PolicyRule{
				{Name: "sneaky-allow", Expression: `tool.name == "evil"`, Effect: "allow"},
			},
		},
	}

	_, err := config.MergeLocal(base, local, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "allow")
	assert.Contains(t, err.Error(), "sneaky-allow")
}

func TestMergeLocal_AllowRulesAccepted(t *testing.T) {
	base := baseConfig()
	local := &config.LocalOverride{
		Policy: &config.PolicyConfig{
			Rules: []config.PolicyRule{
				{Name: "local-allow", Expression: `tool.name == "safe"`, Effect: "allow"},
			},
		},
	}

	result, err := config.MergeLocal(base, local, true)
	require.NoError(t, err)
	require.Len(t, result.Policy.Rules, 2)
	assert.Equal(t, "local-allow", result.Policy.Rules[0].Name)
	assert.Equal(t, "local", result.Policy.Rules[0].Source)
}

func TestMergeLocal_RedactionAppended(t *testing.T) {
	base := baseConfig()
	local := &config.LocalOverride{
		Redaction: &config.RedactionConfig{
			Patterns: []config.RedactionPattern{
				{Name: "project-key", Pattern: `PROJ_[a-zA-Z0-9]{32}`},
			},
		},
	}

	result, err := config.MergeLocal(base, local, false)
	require.NoError(t, err)
	require.Len(t, result.Redaction.Patterns, 2)
	assert.Equal(t, "api-key", result.Redaction.Patterns[0].Name)
	assert.Equal(t, "project-key", result.Redaction.Patterns[1].Name)
	assert.Equal(t, "local", result.Redaction.Patterns[1].Source)
}

func TestMergeLocal_TimeoutOnlyLowers(t *testing.T) {
	base := baseConfig()
	local := &config.LocalOverride{
		Timeout: "15s",
	}

	result, err := config.MergeLocal(base, local, false)
	require.NoError(t, err)
	assert.Equal(t, "15s", result.Timeout)
}

func TestMergeLocal_TimeoutHigherIgnored(t *testing.T) {
	base := baseConfig()
	local := &config.LocalOverride{
		Timeout: "120s",
	}

	result, err := config.MergeLocal(base, local, false)
	require.NoError(t, err)
	assert.Equal(t, "60s", result.Timeout)
}

func TestMergeLocal_ApprovalTimeoutOnlyLowers(t *testing.T) {
	base := baseConfig()
	local := &config.LocalOverride{
		ApprovalTimeout: "30s",
	}

	result, err := config.MergeLocal(base, local, false)
	require.NoError(t, err)
	assert.Equal(t, "30s", result.ApprovalTimeout)
}

func TestMergeLocal_ApprovalTimeoutHigherIgnored(t *testing.T) {
	base := baseConfig()
	local := &config.LocalOverride{
		ApprovalTimeout: "5m",
	}

	result, err := config.MergeLocal(base, local, false)
	require.NoError(t, err)
	assert.Equal(t, "2m", result.ApprovalTimeout)
}

func TestMergeLocal_MaxOutputBytesOnlyLowers(t *testing.T) {
	base := baseConfig()
	lower := 524288
	local := &config.LocalOverride{
		MaxOutputBytes: &lower,
	}

	result, err := config.MergeLocal(base, local, false)
	require.NoError(t, err)
	assert.Equal(t, 524288, result.MaxOutputBytes)
}

func TestMergeLocal_MaxOutputBytesHigherIgnored(t *testing.T) {
	base := baseConfig()
	higher := 2097152
	local := &config.LocalOverride{
		MaxOutputBytes: &higher,
	}

	result, err := config.MergeLocal(base, local, false)
	require.NoError(t, err)
	assert.Equal(t, 1048576, result.MaxOutputBytes)
}

func TestMergeLocal_PolicyDefaultUnchangeable(t *testing.T) {
	// This is validated during LoadLocal, so MergeLocal won't see it.
	// But if someone constructs a LocalOverride manually with Default set,
	// MergeLocal should still ignore it (the field is on PolicyConfig but
	// LoadLocal rejects it).
	base := baseConfig()
	local := &config.LocalOverride{
		Policy: &config.PolicyConfig{
			Default: "allow", // should not be applied
			Rules: []config.PolicyRule{
				{Name: "block-x", Expression: `tool.name == "x"`, Effect: "deny"},
			},
		},
	}

	// MergeLocal should reject if Default is set
	_, err := config.MergeLocal(base, local, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "policy.default")
}

func TestMergeLocal_DuplicateRuleNames(t *testing.T) {
	base := baseConfig()
	local := &config.LocalOverride{
		Policy: &config.PolicyConfig{
			Rules: []config.PolicyRule{
				{Name: "allow-echo", Expression: `tool.name == "echo"`, Effect: "deny"},
			},
		},
	}

	_, err := config.MergeLocal(base, local, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "allow-echo")
	assert.Contains(t, err.Error(), "duplicate")
}

func TestMergeLocal_DuplicateRedactionNames(t *testing.T) {
	base := baseConfig()
	local := &config.LocalOverride{
		Redaction: &config.RedactionConfig{
			Patterns: []config.RedactionPattern{
				{Name: "api-key", Pattern: `new-pattern`},
			},
		},
	}

	_, err := config.MergeLocal(base, local, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "api-key")
	assert.Contains(t, err.Error(), "duplicate")
}

func TestMergeLocal_LogLevelOverride(t *testing.T) {
	base := baseConfig()
	local := &config.LocalOverride{
		LogLevel: "debug",
	}

	result, err := config.MergeLocal(base, local, false)
	require.NoError(t, err)
	assert.Equal(t, "debug", result.LogLevel)
}

func TestMergeLocal_DoesNotMutateBase(t *testing.T) {
	base := baseConfig()
	originalRuleCount := len(base.Policy.Rules)
	originalPatternCount := len(base.Redaction.Patterns)

	local := &config.LocalOverride{
		Policy: &config.PolicyConfig{
			Rules: []config.PolicyRule{
				{Name: "block-rm", Expression: `tool.name == "rm"`, Effect: "deny"},
			},
		},
		Redaction: &config.RedactionConfig{
			Patterns: []config.RedactionPattern{
				{Name: "new-pattern", Pattern: `NEW_[a-z]+`},
			},
		},
	}

	_, err := config.MergeLocal(base, local, false)
	require.NoError(t, err)

	// Base should not be mutated
	assert.Len(t, base.Policy.Rules, originalRuleCount)
	assert.Len(t, base.Redaction.Patterns, originalPatternCount)
}
