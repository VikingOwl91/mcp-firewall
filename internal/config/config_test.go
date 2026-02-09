package config_test

import (
	"strings"
	"testing"
	"time"

	"github.com/VikingOwl91/mcp-firewall/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad_ValidMultiDownstream(t *testing.T) {
	cfg, err := config.Load("../../testdata/config/valid.yaml")
	require.NoError(t, err)

	require.Len(t, cfg.Downstreams, 2)

	echo := cfg.Downstreams["echoserver"]
	assert.Equal(t, "./testdata/echoserver/echoserver", echo.Command)
	assert.Equal(t, []string{"--verbose"}, echo.Args)
	assert.Equal(t, []string{"FOO=bar"}, echo.Env)
	assert.Equal(t, "10s", echo.Timeout)

	another := cfg.Downstreams["another"]
	assert.Equal(t, "./another-server", another.Command)
	assert.Empty(t, another.Timeout)

	assert.Equal(t, "deny", cfg.Policy.Default)
	require.Len(t, cfg.Policy.Rules, 1)
	assert.Equal(t, "allow-echo", cfg.Policy.Rules[0].Name)
	assert.Equal(t, "allow", cfg.Policy.Rules[0].Effect)

	require.Len(t, cfg.Redaction.Patterns, 1)
	assert.Equal(t, "api-key", cfg.Redaction.Patterns[0].Name)
	assert.Equal(t, `sk-[a-zA-Z0-9]{32}`, cfg.Redaction.Patterns[0].Pattern)

	assert.Equal(t, "debug", cfg.LogLevel)
	assert.Equal(t, "30s", cfg.Timeout)
	assert.Equal(t, 524288, cfg.MaxOutputBytes)

	assert.Equal(t, 10*time.Second, cfg.ResolvedTimeout("echoserver"))
	assert.Equal(t, 30*time.Second, cfg.ResolvedTimeout("another"))
}

func TestLoad_ValidMinimal(t *testing.T) {
	cfg, err := config.Load("../../testdata/config/valid_minimal.yaml")
	require.NoError(t, err)

	require.Len(t, cfg.Downstreams, 1)
	assert.Equal(t, "echo", cfg.Downstreams["myserver"].Command)
	assert.Equal(t, "deny", cfg.Policy.Default)
	assert.Equal(t, "info", cfg.LogLevel)
	assert.Equal(t, "60s", cfg.Timeout)
	assert.Equal(t, 1048576, cfg.MaxOutputBytes)
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := config.Load("nonexistent.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonexistent.yaml")
}

func TestLoad_InvalidYAML(t *testing.T) {
	_, err := config.Load("../../testdata/config/invalid.yaml")
	require.Error(t, err)
}

func TestLoad_OldFormatError(t *testing.T) {
	_, err := config.Load("../../testdata/config/old_format.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "downstreams")
}

func TestValidate_EmptyDownstreams(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one downstream")
}

func TestValidate_NilDownstreams(t *testing.T) {
	cfg := &config.Config{}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one downstream")
}

func TestValidate_InvalidAlias(t *testing.T) {
	tests := []struct {
		alias string
	}{
		{"has spaces"},
		{"has.dots"},
		{"has/slashes"},
		{"has@at"},
		{""},
	}
	for _, tt := range tests {
		t.Run(tt.alias, func(t *testing.T) {
			cfg := &config.Config{
				Downstreams: map[string]config.ServerConfig{
					tt.alias: {Command: "echo"},
				},
			}
			err := cfg.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "alias")
		})
	}
}

func TestValidate_AliasTooLong(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			strings.Repeat("a", 33): {Command: "echo"},
		},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "32")
}

func TestValidate_MissingDownstreamCommand(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: ""},
		},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "command")
}

func TestValidate_InvalidPolicyDefault(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo"},
		},
		Policy: config.PolicyConfig{Default: "maybe"},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "policy default")
}

func TestValidate_InvalidPolicyEffect(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo"},
		},
		Policy: config.PolicyConfig{
			Rules: []config.PolicyRule{
				{Name: "rule1", Expression: "true", Effect: "maybe"},
			},
		},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "effect")
}

func TestValidate_DuplicateRuleNames(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo"},
		},
		Policy: config.PolicyConfig{
			Rules: []config.PolicyRule{
				{Name: "rule1", Expression: "true", Effect: "allow"},
				{Name: "rule1", Expression: "true", Effect: "deny"},
			},
		},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate")
}

func TestValidate_DefaultPolicyDefault(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo"},
		},
	}
	err := cfg.Validate()
	require.NoError(t, err)
	assert.Equal(t, "deny", cfg.Policy.Default)
}

func TestValidate_DefaultLogLevel(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo"},
		},
	}
	err := cfg.Validate()
	require.NoError(t, err)
	assert.Equal(t, "info", cfg.LogLevel)
}

func TestValidate_InvalidCELExpression(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo"},
		},
		Policy: config.PolicyConfig{
			Rules: []config.PolicyRule{
				{Name: "bad", Expression: "not valid cel !!!", Effect: "allow"},
			},
		},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CEL")
}

func TestLoad_InvalidPolicy(t *testing.T) {
	_, err := config.Load("../../testdata/config/invalid_policy.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CEL")
}

func TestValidate_DefaultTimeout(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo"},
		},
	}
	err := cfg.Validate()
	require.NoError(t, err)
	assert.Equal(t, "60s", cfg.Timeout)
}

func TestValidate_DefaultMaxOutputBytes(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo"},
		},
	}
	err := cfg.Validate()
	require.NoError(t, err)
	assert.Equal(t, 1048576, cfg.MaxOutputBytes)
}

func TestValidate_InvalidTimeout(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo"},
		},
		Timeout: "not-a-duration",
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timeout")
}

func TestValidate_InvalidDownstreamTimeout(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo", Timeout: "bad"},
		},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timeout")
}

func TestValidate_PerDownstreamTimeout(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"fast": {Command: "echo", Timeout: "5s"},
			"slow": {Command: "echo", Timeout: "120s"},
		},
	}
	err := cfg.Validate()
	require.NoError(t, err)
	assert.Equal(t, "5s", cfg.Downstreams["fast"].Timeout)
	assert.Equal(t, "120s", cfg.Downstreams["slow"].Timeout)
}

func TestValidate_MaxOutputBytesZero(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo"},
		},
		MaxOutputBytes: 0, // zero gets defaulted, not rejected
	}
	err := cfg.Validate()
	require.NoError(t, err)
	assert.Equal(t, 1048576, cfg.MaxOutputBytes)
}

func TestValidate_MaxOutputBytesNegative(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo"},
		},
		MaxOutputBytes: -1,
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "max_output_bytes")
}

func TestResolvedTimeout_Global(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo"},
		},
		Timeout: "30s",
	}
	require.NoError(t, cfg.Validate())

	d := cfg.ResolvedTimeout("myserver")
	assert.Equal(t, 30*time.Second, d)
}

func TestResolvedTimeout_PerDownstreamOverride(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"fast":   {Command: "echo", Timeout: "5s"},
			"normal": {Command: "echo"},
		},
		Timeout: "60s",
	}
	require.NoError(t, cfg.Validate())

	assert.Equal(t, 5*time.Second, cfg.ResolvedTimeout("fast"))
	assert.Equal(t, 60*time.Second, cfg.ResolvedTimeout("normal"))
}

func TestValidate_PromptEffectInRule(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo"},
		},
		Policy: config.PolicyConfig{
			Rules: []config.PolicyRule{
				{Name: "ask-first", Expression: "true", Effect: "prompt"},
			},
		},
	}
	err := cfg.Validate()
	require.NoError(t, err)
}

func TestValidate_PromptEffectInDefault(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo"},
		},
		Policy: config.PolicyConfig{Default: "prompt"},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "policy default")
}

func TestValidate_PromptRuleWithMessage(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo"},
		},
		Policy: config.PolicyConfig{
			Rules: []config.PolicyRule{
				{Name: "ask-first", Expression: "true", Effect: "prompt", Message: "requires approval"},
			},
		},
	}
	err := cfg.Validate()
	require.NoError(t, err)
}

func TestValidate_RedactionPatternsValid(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo"},
		},
		Redaction: config.RedactionConfig{
			Patterns: []config.RedactionPattern{
				{Name: "api-key", Pattern: `sk-[a-zA-Z0-9]{32}`},
				{Name: "email", Pattern: `[\w.+-]+@[\w-]+\.[\w.]+`},
			},
		},
	}
	err := cfg.Validate()
	require.NoError(t, err)
}

func TestValidate_RedactionPatternsInvalidRegex(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo"},
		},
		Redaction: config.RedactionConfig{
			Patterns: []config.RedactionPattern{
				{Name: "bad", Pattern: `[invalid`},
			},
		},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bad")
}

func TestValidate_RedactionPatternsEmpty(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo"},
		},
	}
	err := cfg.Validate()
	require.NoError(t, err)
}

func TestValidate_RedactionPatternMissingName(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo"},
		},
		Redaction: config.RedactionConfig{
			Patterns: []config.RedactionPattern{
				{Name: "", Pattern: `secret`},
			},
		},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "name")
}

func TestValidate_RedactionPatternMissingPattern(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo"},
		},
		Redaction: config.RedactionConfig{
			Patterns: []config.RedactionPattern{
				{Name: "empty-pat", Pattern: ""},
			},
		},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pattern")
}

func TestValidate_RedactionDuplicateNames(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo"},
		},
		Redaction: config.RedactionConfig{
			Patterns: []config.RedactionPattern{
				{Name: "secret", Pattern: `secret`},
				{Name: "secret", Pattern: `other`},
			},
		},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate")
}

func TestValidate_ValidAliases(t *testing.T) {
	tests := []string{"myserver", "my-server", "my_server", "Server1", "a", "abc-123_DEF"}
	for _, alias := range tests {
		t.Run(alias, func(t *testing.T) {
			cfg := &config.Config{
				Downstreams: map[string]config.ServerConfig{
					alias: {Command: "echo"},
				},
			}
			err := cfg.Validate()
			require.NoError(t, err)
		})
	}
}
