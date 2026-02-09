package config

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/google/cel-go/cel"
	"gopkg.in/yaml.v3"
)

var aliasPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

type ServerConfig struct {
	Command string   `yaml:"command"`
	Args    []string `yaml:"args,omitempty"`
	Env     []string `yaml:"env,omitempty"`
	Timeout string   `yaml:"timeout,omitempty"`
}

type PolicyRule struct {
	Name       string `yaml:"name" json:"name"`
	Expression string `yaml:"expression" json:"expression"`
	Effect     string `yaml:"effect" json:"effect"`
	Message    string `yaml:"message,omitempty" json:"message,omitempty"`
	Source     string `yaml:"source,omitempty" json:"source,omitempty"`
}

type PolicyConfig struct {
	Default string       `yaml:"default" json:"default,omitempty"`
	Rules   []PolicyRule `yaml:"rules,omitempty" json:"rules,omitempty"`
}

type RedactionPattern struct {
	Name    string `yaml:"name" json:"name"`
	Pattern string `yaml:"pattern" json:"pattern"`
	Source  string `yaml:"source,omitempty" json:"source,omitempty"`
}

type RedactionConfig struct {
	Patterns []RedactionPattern `yaml:"patterns,omitempty" json:"patterns,omitempty"`
}

type Config struct {
	Downstreams     map[string]ServerConfig `yaml:"downstreams"`
	Policy          PolicyConfig            `yaml:"policy,omitempty"`
	Redaction       RedactionConfig         `yaml:"redaction,omitempty"`
	LogLevel        string                  `yaml:"log_level"`
	Timeout         string                  `yaml:"timeout,omitempty"`
	MaxOutputBytes  int                     `yaml:"max_output_bytes,omitempty"`
	ApprovalTimeout string                  `yaml:"approval_timeout,omitempty"`
}

// GlobalConfig is the top-level config file structure supporting named profiles.
type GlobalConfig struct {
	Profiles       map[string]Config `yaml:"profiles,omitempty"`
	AllowExpansion bool              `yaml:"allow_expansion,omitempty"`
	Config         `yaml:",inline"`
}

// oldConfig detects the deprecated singular "downstream:" key.
type oldConfig struct {
	Downstream *ServerConfig `yaml:"downstream"`
}

// LoadGlobal loads the global config file and returns a GlobalConfig.
func LoadGlobal(path string) (*GlobalConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}

	// Check for old format
	var old oldConfig
	if err := yaml.Unmarshal(data, &old); err == nil && old.Downstream != nil {
		return nil, fmt.Errorf("parsing config %s: old format detected — use 'downstreams:' (plural map) instead of 'downstream:'", path)
	}

	var gc GlobalConfig
	if err := yaml.Unmarshal(data, &gc); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}

	return &gc, nil
}

// ResolvedConfig holds the result of ResolveConfig.
type ResolvedConfig struct {
	Config        *Config
	ProfileName   string // resolved profile name ("" for default)
	LocalOverride string // path to local override file ("" if none)
}

// localOverrideNames are the filenames checked in a workspace directory.
var localOverrideNames = []string{
	".mcp-firewall.yaml",
	".mcp-firewall.yml",
	".mcp-firewall.json",
}

// ResolveConfig is the full pipeline:
// 1. LoadGlobal(configPath)
// 2. ResolveProfile(gc, profileName)
// 3. If workspacePath set, look for .mcp-firewall.{yaml,yml,json}, LoadLocal, MergeLocal
// Returns the effective config with provenance metadata.
func ResolveConfig(configPath, profileName, workspacePath string) (*ResolvedConfig, error) {
	gc, err := LoadGlobal(configPath)
	if err != nil {
		return nil, err
	}

	cfg, resolvedProfile, err := ResolveProfile(gc, profileName)
	if err != nil {
		return nil, err
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validating resolved config: %w", err)
	}

	// Stamp provenance on base rules/patterns
	source := "base"
	if resolvedProfile != "" {
		source = "profile:" + resolvedProfile
	}
	for i := range cfg.Policy.Rules {
		if cfg.Policy.Rules[i].Source == "" {
			cfg.Policy.Rules[i].Source = source
		}
	}
	for i := range cfg.Redaction.Patterns {
		if cfg.Redaction.Patterns[i].Source == "" {
			cfg.Redaction.Patterns[i].Source = source
		}
	}

	result := &ResolvedConfig{
		Config:      cfg,
		ProfileName: resolvedProfile,
	}

	if workspacePath != "" {
		localPath := findLocalOverride(workspacePath)
		if localPath != "" {
			local, err := LoadLocal(localPath)
			if err != nil {
				return nil, err
			}
			cfg, err = MergeLocal(cfg, local, gc.AllowExpansion)
			if err != nil {
				return nil, fmt.Errorf("merging local override: %w", err)
			}
			result.Config = cfg
			result.LocalOverride = localPath
		}
	}

	return result, nil
}

// findLocalOverride checks for .mcp-firewall.{yaml,yml,json} in dir.
func findLocalOverride(dir string) string {
	for _, name := range localOverrideNames {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}

// DetectWorkspace walks up from startDir looking for a local override file.
// Stops at the filesystem root. Returns "" if none found.
func DetectWorkspace(startDir string) string {
	dir, err := filepath.Abs(startDir)
	if err != nil {
		return ""
	}
	for {
		if findLocalOverride(dir) != "" {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}

	// Check for old format
	var old oldConfig
	if err := yaml.Unmarshal(data, &old); err == nil && old.Downstream != nil {
		return nil, fmt.Errorf("parsing config %s: old format detected — use 'downstreams:' (plural map) instead of 'downstream:'", path)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validating config %s: %w", path, err)
	}

	return &cfg, nil
}

func (c *Config) Validate() error {
	if len(c.Downstreams) == 0 {
		return fmt.Errorf("at least one downstream is required")
	}

	for alias, sc := range c.Downstreams {
		if err := validateAlias(alias); err != nil {
			return err
		}
		if sc.Command == "" {
			return fmt.Errorf("downstream %q: command is required", alias)
		}
		if sc.Timeout != "" {
			if _, err := time.ParseDuration(sc.Timeout); err != nil {
				return fmt.Errorf("downstream %q: invalid timeout %q: %w", alias, sc.Timeout, err)
			}
		}
	}

	if c.Timeout == "" {
		c.Timeout = "60s"
	}
	if _, err := time.ParseDuration(c.Timeout); err != nil {
		return fmt.Errorf("invalid timeout %q: %w", c.Timeout, err)
	}

	if c.MaxOutputBytes < 0 {
		return fmt.Errorf("max_output_bytes must be positive, got %d", c.MaxOutputBytes)
	}
	if c.MaxOutputBytes == 0 {
		c.MaxOutputBytes = 1048576
	}

	if c.ApprovalTimeout == "" {
		c.ApprovalTimeout = "2m"
	}
	if _, err := time.ParseDuration(c.ApprovalTimeout); err != nil {
		return fmt.Errorf("invalid approval_timeout %q: %w", c.ApprovalTimeout, err)
	}

	if err := c.validatePolicy(); err != nil {
		return err
	}

	if err := c.validateRedaction(); err != nil {
		return err
	}

	if c.LogLevel == "" {
		c.LogLevel = "info"
	}

	return nil
}

func (c *Config) ResolvedApprovalTimeout() time.Duration {
	d, _ := time.ParseDuration(c.ApprovalTimeout)
	return d
}

func (c *Config) ResolvedTimeout(alias string) time.Duration {
	if sc, ok := c.Downstreams[alias]; ok && sc.Timeout != "" {
		d, _ := time.ParseDuration(sc.Timeout)
		return d
	}
	d, _ := time.ParseDuration(c.Timeout)
	return d
}

func validateAlias(alias string) error {
	if alias == "" {
		return fmt.Errorf("downstream alias must not be empty")
	}
	if len(alias) > 32 {
		return fmt.Errorf("downstream alias %q exceeds 32 characters", alias)
	}
	if !aliasPattern.MatchString(alias) {
		return fmt.Errorf("downstream alias %q must match [a-zA-Z0-9_-]+", alias)
	}
	return nil
}

func (c *Config) validatePolicy() error {
	if c.Policy.Default == "" {
		c.Policy.Default = "deny"
	}
	if c.Policy.Default != "allow" && c.Policy.Default != "deny" {
		return fmt.Errorf("policy default must be 'allow' or 'deny', got %q", c.Policy.Default)
	}

	seen := make(map[string]bool)
	for i, rule := range c.Policy.Rules {
		if rule.Effect != "allow" && rule.Effect != "deny" && rule.Effect != "prompt" {
			return fmt.Errorf("rule %d (%q): effect must be 'allow', 'deny', or 'prompt', got %q", i, rule.Name, rule.Effect)
		}
		if seen[rule.Name] {
			return fmt.Errorf("rule %d: duplicate rule name %q", i, rule.Name)
		}
		seen[rule.Name] = true
	}

	if err := validateCELExpressions(c.Policy.Rules); err != nil {
		return err
	}

	return nil
}

func (c *Config) validateRedaction() error {
	seen := make(map[string]bool)
	for i, p := range c.Redaction.Patterns {
		if p.Name == "" {
			return fmt.Errorf("redaction pattern %d: name is required", i)
		}
		if p.Pattern == "" {
			return fmt.Errorf("redaction pattern %q: pattern is required", p.Name)
		}
		if _, err := regexp.Compile(p.Pattern); err != nil {
			return fmt.Errorf("redaction pattern %q: invalid regex: %w", p.Name, err)
		}
		if seen[p.Name] {
			return fmt.Errorf("redaction pattern %d: duplicate name %q", i, p.Name)
		}
		seen[p.Name] = true
	}
	return nil
}

func validateCELExpressions(rules []PolicyRule) error {
	if len(rules) == 0 {
		return nil
	}

	env, err := cel.NewEnv(
		cel.Variable("method", cel.StringType),
		cel.Variable("server", cel.StringType),
		cel.Variable("tool", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("resource", cel.MapType(cel.StringType, cel.DynType)),
	)
	if err != nil {
		return fmt.Errorf("creating CEL environment: %w", err)
	}

	for _, rule := range rules {
		_, issues := env.Compile(rule.Expression)
		if issues != nil && issues.Err() != nil {
			return fmt.Errorf("rule %q: invalid CEL expression: %w", rule.Name, issues.Err())
		}
	}

	return nil
}
