package config_test

import (
	"testing"

	"github.com/VikingOwl91/mcp-firewall/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad_ValidConfig(t *testing.T) {
	cfg, err := config.Load("../../testdata/config/valid.yaml")
	require.NoError(t, err)

	assert.Equal(t, "./testdata/echoserver/echoserver", cfg.Downstream.Command)
	assert.Equal(t, []string{"--verbose"}, cfg.Downstream.Args)
	assert.Equal(t, []string{"FOO=bar"}, cfg.Downstream.Env)
	assert.Equal(t, "debug", cfg.LogLevel)
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

func TestValidate_MissingCommand(t *testing.T) {
	cfg := &config.Config{
		Downstream: config.ServerConfig{Command: ""},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "command")
}

func TestValidate_DefaultLogLevel(t *testing.T) {
	cfg := &config.Config{
		Downstream: config.ServerConfig{Command: "echo"},
	}
	err := cfg.Validate()
	require.NoError(t, err)
	assert.Equal(t, "info", cfg.LogLevel)
}
