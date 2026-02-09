package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/VikingOwl91/mcp-firewall/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Full pipeline integration tests ---

func TestResolveConfig_ProvenanceStamped_Base(t *testing.T) {
	resolved, err := config.ResolveConfig("../../testdata/config/valid.yaml", "", "")
	require.NoError(t, err)

	for _, rule := range resolved.Config.Policy.Rules {
		assert.Equal(t, "base", rule.Source, "rule %q should have source 'base'", rule.Name)
	}
	for _, pat := range resolved.Config.Redaction.Patterns {
		assert.Equal(t, "base", pat.Source, "pattern %q should have source 'base'", pat.Name)
	}
}

func TestResolveConfig_ProvenanceStamped_Profile(t *testing.T) {
	resolved, err := config.ResolveConfig("../../testdata/config/profiles.yaml", "strict", "")
	require.NoError(t, err)

	require.Len(t, resolved.Config.Policy.Rules, 1)
	assert.Equal(t, "profile:strict", resolved.Config.Policy.Rules[0].Source)
	assert.Equal(t, "strict", resolved.ProfileName)
}

func TestResolveConfig_ProvenanceStamped_LocalMerge(t *testing.T) {
	dir := t.TempDir()
	writeTestLocal(t, dir, `
policy:
  rules:
    - name: block-exec
      expression: 'tool.name == "exec"'
      effect: deny
`)

	resolved, err := config.ResolveConfig("../../testdata/config/valid.yaml", "", dir)
	require.NoError(t, err)

	// Local rule should be first with source "local"
	require.True(t, len(resolved.Config.Policy.Rules) >= 2)
	assert.Equal(t, "block-exec", resolved.Config.Policy.Rules[0].Name)
	assert.Equal(t, "local", resolved.Config.Policy.Rules[0].Source)

	// Base rule should be second with source "base"
	assert.Equal(t, "allow-echo", resolved.Config.Policy.Rules[1].Name)
	assert.Equal(t, "base", resolved.Config.Policy.Rules[1].Source)

	// LocalOverride path recorded
	assert.NotEmpty(t, resolved.LocalOverride)
}

func TestResolveConfig_AllowExpansionTrue(t *testing.T) {
	// Create a global config with allow_expansion: true
	dir := t.TempDir()
	globalPath := filepath.Join(dir, "config.yaml")
	writeTestFile(t, globalPath, `
allow_expansion: true
downstreams:
  echoserver:
    command: echo
policy:
  default: deny
  rules:
    - name: base-rule
      expression: 'tool.name == "safe"'
      effect: allow
`)

	workDir := t.TempDir()
	writeTestLocal(t, workDir, `
policy:
  rules:
    - name: local-allow
      expression: 'tool.name == "extra"'
      effect: allow
`)

	resolved, err := config.ResolveConfig(globalPath, "", workDir)
	require.NoError(t, err)
	// Both rules should be present — local allow accepted because allow_expansion=true
	require.Len(t, resolved.Config.Policy.Rules, 2)
	assert.Equal(t, "local-allow", resolved.Config.Policy.Rules[0].Name)
	assert.Equal(t, "base-rule", resolved.Config.Policy.Rules[1].Name)
}

func TestResolveConfig_AllowExpansionFalse_RejectsLocalAllow(t *testing.T) {
	dir := t.TempDir()
	globalPath := filepath.Join(dir, "config.yaml")
	writeTestFile(t, globalPath, `
downstreams:
  echoserver:
    command: echo
policy:
  default: deny
  rules:
    - name: base-rule
      expression: 'tool.name == "safe"'
      effect: allow
`)

	workDir := t.TempDir()
	writeTestLocal(t, workDir, `
policy:
  rules:
    - name: sneaky-allow
      expression: 'tool.name == "evil"'
      effect: allow
`)

	_, err := config.ResolveConfig(globalPath, "", workDir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "allow")
	assert.Contains(t, err.Error(), "sneaky-allow")
}

func TestResolveConfig_InvalidProfile_Config(t *testing.T) {
	dir := t.TempDir()
	globalPath := filepath.Join(dir, "config.yaml")
	writeTestFile(t, globalPath, `
downstreams:
  echoserver:
    command: echo
profiles:
  broken:
    downstreams: {}
`)

	_, err := config.ResolveConfig(globalPath, "broken", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one downstream")
}

func TestResolveConfig_LocalTimeoutLowers(t *testing.T) {
	workDir := t.TempDir()
	writeTestLocal(t, workDir, `
timeout: 10s
`)

	resolved, err := config.ResolveConfig("../../testdata/config/valid.yaml", "", workDir)
	require.NoError(t, err)
	// valid.yaml has timeout: 30s, local has 10s → should be 10s
	assert.Equal(t, "10s", resolved.Config.Timeout)
}

func TestResolveConfig_LocalTimeoutHigherIgnored(t *testing.T) {
	workDir := t.TempDir()
	writeTestLocal(t, workDir, `
timeout: 120s
`)

	resolved, err := config.ResolveConfig("../../testdata/config/valid.yaml", "", workDir)
	require.NoError(t, err)
	// valid.yaml has timeout: 30s, local has 120s → should stay 30s
	assert.Equal(t, "30s", resolved.Config.Timeout)
}

func TestResolveConfig_LocalRedactionAppended(t *testing.T) {
	workDir := t.TempDir()
	writeTestLocal(t, workDir, `
redaction:
  patterns:
    - name: project-secret
      pattern: 'PROJ_[a-z]+'
`)

	resolved, err := config.ResolveConfig("../../testdata/config/valid.yaml", "", workDir)
	require.NoError(t, err)
	// valid.yaml has 1 redaction pattern, local adds 1 more
	require.Len(t, resolved.Config.Redaction.Patterns, 2)
	assert.Equal(t, "api-key", resolved.Config.Redaction.Patterns[0].Name)
	assert.Equal(t, "base", resolved.Config.Redaction.Patterns[0].Source)
	assert.Equal(t, "project-secret", resolved.Config.Redaction.Patterns[1].Name)
	assert.Equal(t, "local", resolved.Config.Redaction.Patterns[1].Source)
}

func TestResolveConfig_LocalDuplicateRuleNameRejected(t *testing.T) {
	workDir := t.TempDir()
	writeTestLocal(t, workDir, `
policy:
  rules:
    - name: allow-echo
      expression: 'tool.name == "echo"'
      effect: deny
`)

	_, err := config.ResolveConfig("../../testdata/config/valid.yaml", "", workDir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "allow-echo")
	assert.Contains(t, err.Error(), "duplicate")
}

func TestResolveConfig_LocalDuplicateRedactionNameRejected(t *testing.T) {
	workDir := t.TempDir()
	writeTestLocal(t, workDir, `
redaction:
  patterns:
    - name: api-key
      pattern: 'duplicate'
`)

	_, err := config.ResolveConfig("../../testdata/config/valid.yaml", "", workDir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "api-key")
	assert.Contains(t, err.Error(), "duplicate")
}

func TestResolveConfig_LocalWithDownstreamsRejected(t *testing.T) {
	workDir := t.TempDir()
	writeTestLocal(t, workDir, `
downstreams:
  evil:
    command: ./evil
`)

	_, err := config.ResolveConfig("../../testdata/config/valid.yaml", "", workDir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "downstreams")
}

func TestResolveConfig_LocalWithPolicyDefaultRejected(t *testing.T) {
	workDir := t.TempDir()
	writeTestLocal(t, workDir, `
policy:
  default: allow
  rules:
    - name: x
      expression: 'true'
      effect: deny
`)

	_, err := config.ResolveConfig("../../testdata/config/valid.yaml", "", workDir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "policy.default")
}

func TestResolveConfig_EnvProfileSelection(t *testing.T) {
	t.Setenv("MCP_FIREWALL_PROFILE", "development")
	resolved, err := config.ResolveConfig("../../testdata/config/profiles.yaml", "", "")
	require.NoError(t, err)
	assert.Equal(t, "./echoserver-dev", resolved.Config.Downstreams["echoserver"].Command)
	assert.Equal(t, "development", resolved.ProfileName)
}

func TestResolveConfig_ExplicitProfileOverridesEnv(t *testing.T) {
	t.Setenv("MCP_FIREWALL_PROFILE", "development")
	resolved, err := config.ResolveConfig("../../testdata/config/profiles.yaml", "strict", "")
	require.NoError(t, err)
	assert.Equal(t, "deny", resolved.Config.Policy.Default)
	require.Len(t, resolved.Config.Policy.Rules, 1)
	assert.Equal(t, "prompt-all-tools", resolved.Config.Policy.Rules[0].Name)
	assert.Equal(t, "strict", resolved.ProfileName)
}

func TestResolveConfig_ProfilePlusLocalMerge(t *testing.T) {
	workDir := t.TempDir()
	writeTestLocal(t, workDir, `
policy:
  rules:
    - name: block-exec
      expression: 'tool.name == "exec"'
      effect: deny
timeout: 30s
`)

	resolved, err := config.ResolveConfig("../../testdata/config/profiles.yaml", "strict", workDir)
	require.NoError(t, err)

	// Profile config
	assert.Equal(t, "deny", resolved.Config.Policy.Default)

	// Local rule prepended before profile rules
	require.Len(t, resolved.Config.Policy.Rules, 2)
	assert.Equal(t, "block-exec", resolved.Config.Policy.Rules[0].Name)
	assert.Equal(t, "local", resolved.Config.Policy.Rules[0].Source)
	assert.Equal(t, "prompt-all-tools", resolved.Config.Policy.Rules[1].Name)
	assert.Equal(t, "profile:strict", resolved.Config.Policy.Rules[1].Source)

	// strict profile has no timeout set → defaults to 60s
	// local has 30s which is lower → 30s should win
	assert.Equal(t, "30s", resolved.Config.Timeout)

	// strict profile has approval_timeout: 1m
	// local doesn't set one → should stay 1m
	assert.Equal(t, "1m", resolved.Config.ApprovalTimeout)

	// Provenance metadata
	assert.Equal(t, "strict", resolved.ProfileName)
	assert.NotEmpty(t, resolved.LocalOverride)
}

func TestResolveConfig_EmptyLocalOverrideIsNoOp(t *testing.T) {
	workDir := t.TempDir()
	writeTestLocal(t, workDir, `
# empty override — just a comment
`)

	resolved, err := config.ResolveConfig("../../testdata/config/valid.yaml", "", workDir)
	require.NoError(t, err)
	// Should be identical to loading without local
	assert.Equal(t, "deny", resolved.Config.Policy.Default)
	assert.Len(t, resolved.Config.Policy.Rules, 1)
	assert.Equal(t, "30s", resolved.Config.Timeout)
}

func TestResolveConfig_LogLevelOverrideFromLocal(t *testing.T) {
	workDir := t.TempDir()
	writeTestLocal(t, workDir, `
log_level: warn
`)

	resolved, err := config.ResolveConfig("../../testdata/config/valid.yaml", "", workDir)
	require.NoError(t, err)
	assert.Equal(t, "warn", resolved.Config.LogLevel)
}

func TestResolveConfig_MaxOutputBytesLowered(t *testing.T) {
	workDir := t.TempDir()
	writeTestLocal(t, workDir, `
max_output_bytes: 1024
`)

	resolved, err := config.ResolveConfig("../../testdata/config/valid.yaml", "", workDir)
	require.NoError(t, err)
	// valid.yaml has 524288, local wants 1024 → should be 1024
	assert.Equal(t, 1024, resolved.Config.MaxOutputBytes)
}

func TestResolveConfig_MaxOutputBytesHigherIgnored(t *testing.T) {
	workDir := t.TempDir()
	writeTestLocal(t, workDir, `
max_output_bytes: 2097152
`)

	resolved, err := config.ResolveConfig("../../testdata/config/valid.yaml", "", workDir)
	require.NoError(t, err)
	// valid.yaml has 524288, local wants 2097152 → should stay 524288
	assert.Equal(t, 524288, resolved.Config.MaxOutputBytes)
}

func TestResolveConfig_ProvenanceStamped_EnvProfile(t *testing.T) {
	t.Setenv("MCP_FIREWALL_PROFILE", "strict")
	resolved, err := config.ResolveConfig("../../testdata/config/profiles.yaml", "", "")
	require.NoError(t, err)

	// Profile resolved from env should have correct provenance
	assert.Equal(t, "strict", resolved.ProfileName)
	require.Len(t, resolved.Config.Policy.Rules, 1)
	assert.Equal(t, "profile:strict", resolved.Config.Policy.Rules[0].Source)
}

// --- Local override format tests ---

func TestResolveConfig_LocalOverrideYML(t *testing.T) {
	workDir := t.TempDir()
	ymlPath := filepath.Join(workDir, ".mcp-firewall.yml")
	require.NoError(t, os.WriteFile(ymlPath, []byte(`
policy:
  rules:
    - name: yml-deny
      expression: 'tool.name == "bad"'
      effect: deny
`), 0644))

	resolved, err := config.ResolveConfig("../../testdata/config/valid_minimal.yaml", "", workDir)
	require.NoError(t, err)
	require.Len(t, resolved.Config.Policy.Rules, 1)
	assert.Equal(t, "yml-deny", resolved.Config.Policy.Rules[0].Name)
	assert.Equal(t, "local", resolved.Config.Policy.Rules[0].Source)
	assert.Equal(t, ymlPath, resolved.LocalOverride)
}

func TestResolveConfig_LocalOverrideJSON(t *testing.T) {
	workDir := t.TempDir()
	jsonPath := filepath.Join(workDir, ".mcp-firewall.json")
	require.NoError(t, os.WriteFile(jsonPath, []byte(`{
  "policy": {
    "rules": [
      {
        "name": "json-deny",
        "expression": "tool.name == \"bad\"",
        "effect": "deny"
      }
    ]
  }
}`), 0644))

	resolved, err := config.ResolveConfig("../../testdata/config/valid_minimal.yaml", "", workDir)
	require.NoError(t, err)
	require.Len(t, resolved.Config.Policy.Rules, 1)
	assert.Equal(t, "json-deny", resolved.Config.Policy.Rules[0].Name)
	assert.Equal(t, "local", resolved.Config.Policy.Rules[0].Source)
	assert.Equal(t, jsonPath, resolved.LocalOverride)
}

func TestResolveConfig_LocalOverrideYAMLPrecedence(t *testing.T) {
	// When both .yaml and .yml exist, .yaml takes precedence (checked first)
	workDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(workDir, ".mcp-firewall.yaml"), []byte(`
policy:
  rules:
    - name: yaml-rule
      expression: 'true'
      effect: deny
`), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(workDir, ".mcp-firewall.yml"), []byte(`
policy:
  rules:
    - name: yml-rule
      expression: 'true'
      effect: deny
`), 0644))

	resolved, err := config.ResolveConfig("../../testdata/config/valid_minimal.yaml", "", workDir)
	require.NoError(t, err)
	require.Len(t, resolved.Config.Policy.Rules, 1)
	assert.Equal(t, "yaml-rule", resolved.Config.Policy.Rules[0].Name)
}

// --- DetectWorkspace tests ---

func TestDetectWorkspace_Found(t *testing.T) {
	// Create a nested directory structure with .mcp-firewall.yaml at root
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, ".mcp-firewall.yaml"), []byte("{}"), 0644))
	nested := filepath.Join(root, "a", "b", "c")
	require.NoError(t, os.MkdirAll(nested, 0755))

	result := config.DetectWorkspace(nested)
	assert.Equal(t, root, result)
}

func TestDetectWorkspace_NotFound(t *testing.T) {
	dir := t.TempDir()
	result := config.DetectWorkspace(dir)
	assert.Equal(t, "", result)
}

func TestDetectWorkspace_DirectMatch(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".mcp-firewall.yml"), []byte("{}"), 0644))

	result := config.DetectWorkspace(dir)
	assert.Equal(t, dir, result)
}

func TestDetectWorkspace_JSONFormat(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".mcp-firewall.json"), []byte("{}"), 0644))

	result := config.DetectWorkspace(dir)
	assert.Equal(t, dir, result)
}

// --- Helpers ---

func writeTestLocal(t *testing.T, dir, content string) {
	t.Helper()
	path := filepath.Join(dir, ".mcp-firewall.yaml")
	writeTestFile(t, path, content)
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(content), 0644))
}
