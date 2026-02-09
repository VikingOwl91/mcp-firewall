package config

import (
	"fmt"
	"os"
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
	Name       string `yaml:"name"`
	Expression string `yaml:"expression"`
	Effect     string `yaml:"effect"`
	Message    string `yaml:"message,omitempty"`
}

type PolicyConfig struct {
	Default string       `yaml:"default"`
	Rules   []PolicyRule `yaml:"rules,omitempty"`
}

type RedactionPattern struct {
	Name    string `yaml:"name"`
	Pattern string `yaml:"pattern"`
}

type RedactionConfig struct {
	Patterns []RedactionPattern `yaml:"patterns,omitempty"`
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

// oldConfig detects the deprecated singular "downstream:" key.
type oldConfig struct {
	Downstream *ServerConfig `yaml:"downstream"`
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
