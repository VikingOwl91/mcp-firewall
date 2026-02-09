package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type ServerConfig struct {
	Command string   `yaml:"command"`
	Args    []string `yaml:"args,omitempty"`
	Env     []string `yaml:"env,omitempty"`
}

type Config struct {
	Downstream ServerConfig `yaml:"downstream"`
	LogLevel   string       `yaml:"log_level"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
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
	if c.Downstream.Command == "" {
		return fmt.Errorf("downstream command is required")
	}

	if c.LogLevel == "" {
		c.LogLevel = "info"
	}

	return nil
}
