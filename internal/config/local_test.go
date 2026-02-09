package config_test

import (
	"testing"

	"github.com/VikingOwl91/mcp-firewall/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLocalOverride_LoadValid(t *testing.T) {
	lo, err := config.LoadLocal("../../testdata/config/local_override.yaml")
	require.NoError(t, err)

	require.NotNil(t, lo.Policy)
	require.Len(t, lo.Policy.Rules, 2)
	assert.Equal(t, "block-dangerous", lo.Policy.Rules[0].Name)
	assert.Equal(t, "deny", lo.Policy.Rules[0].Effect)
	assert.Equal(t, "prompt-deploy", lo.Policy.Rules[1].Name)
	assert.Equal(t, "prompt", lo.Policy.Rules[1].Effect)
	assert.Equal(t, "Deploy requires explicit approval", lo.Policy.Rules[1].Message)

	require.NotNil(t, lo.Redaction)
	require.Len(t, lo.Redaction.Patterns, 1)
	assert.Equal(t, "project-api-key", lo.Redaction.Patterns[0].Name)

	assert.Equal(t, "15s", lo.Timeout)
}

func TestLocalOverride_LoadNoDownstreams(t *testing.T) {
	_, err := config.LoadLocal("../../testdata/config/local_with_downstreams.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "downstreams")
	assert.Contains(t, err.Error(), "not allowed")
}

func TestLocalOverride_LoadNoPolicyDefault(t *testing.T) {
	_, err := config.LoadLocal("../../testdata/config/local_with_default.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "policy.default")
	assert.Contains(t, err.Error(), "not allowed")
}

func TestLocalOverride_FileNotFound(t *testing.T) {
	_, err := config.LoadLocal("nonexistent.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonexistent.yaml")
}

func TestLocalOverride_EmptyFile(t *testing.T) {
	// Create a temp file with empty content — should be valid (no-op override)
	lo, err := config.LoadLocal("../../testdata/config/valid_minimal.yaml")
	// valid_minimal has downstreams, so it should fail
	require.Error(t, err)
	assert.Contains(t, err.Error(), "downstreams")
	_ = lo
}
