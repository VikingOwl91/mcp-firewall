package config_test

import (
	"testing"

	"github.com/VikingOwl91/mcp-firewall/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newGlobalConfig() *config.GlobalConfig {
	return &config.GlobalConfig{
		Config: config.Config{
			Downstreams: map[string]config.ServerConfig{
				"default-server": {Command: "echo"},
			},
		},
		Profiles: map[string]config.Config{
			"strict": {
				Downstreams: map[string]config.ServerConfig{
					"strict-server": {Command: "strict-cmd"},
				},
				Policy: config.PolicyConfig{Default: "deny"},
			},
			"dev": {
				Downstreams: map[string]config.ServerConfig{
					"dev-server": {Command: "dev-cmd"},
				},
				Policy: config.PolicyConfig{Default: "allow"},
			},
		},
	}
}

func TestResolveProfile_Default(t *testing.T) {
	gc := newGlobalConfig()

	cfg, name, err := config.ResolveProfile(gc, "")
	require.NoError(t, err)
	assert.Equal(t, "echo", cfg.Downstreams["default-server"].Command)
	assert.Equal(t, "", name)
}

func TestResolveProfile_ExplicitName(t *testing.T) {
	gc := newGlobalConfig()

	cfg, name, err := config.ResolveProfile(gc, "strict")
	require.NoError(t, err)
	assert.Equal(t, "strict-cmd", cfg.Downstreams["strict-server"].Command)
	assert.Equal(t, "deny", cfg.Policy.Default)
	assert.Equal(t, "strict", name)
}

func TestResolveProfile_EnvFallback(t *testing.T) {
	gc := newGlobalConfig()
	t.Setenv("MCP_FIREWALL_PROFILE", "dev")

	cfg, name, err := config.ResolveProfile(gc, "")
	require.NoError(t, err)
	assert.Equal(t, "dev-cmd", cfg.Downstreams["dev-server"].Command)
	assert.Equal(t, "allow", cfg.Policy.Default)
	assert.Equal(t, "dev", name)
}

func TestResolveProfile_ExplicitOverridesEnv(t *testing.T) {
	gc := newGlobalConfig()
	t.Setenv("MCP_FIREWALL_PROFILE", "dev")

	cfg, name, err := config.ResolveProfile(gc, "strict")
	require.NoError(t, err)
	assert.Equal(t, "strict-cmd", cfg.Downstreams["strict-server"].Command)
	assert.Equal(t, "strict", name)
}

func TestResolveProfile_NotFound(t *testing.T) {
	gc := newGlobalConfig()

	_, _, err := config.ResolveProfile(gc, "nonexistent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonexistent")
}

func TestResolveProfile_EnvNotFound(t *testing.T) {
	gc := newGlobalConfig()
	t.Setenv("MCP_FIREWALL_PROFILE", "missing")

	_, _, err := config.ResolveProfile(gc, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing")
}
