package config

import (
	"fmt"
	"os"
)

// ResolveProfile selects a profile from GlobalConfig.
// Precedence: explicit name > env MCP_FIREWALL_PROFILE > default (inline).
// Returns the resolved config and the profile name that was used ("" for default).
func ResolveProfile(gc *GlobalConfig, name string) (*Config, string, error) {
	if name == "" {
		name = os.Getenv("MCP_FIREWALL_PROFILE")
	}

	if name == "" {
		cfg := gc.Config
		return &cfg, "", nil
	}

	profile, ok := gc.Profiles[name]
	if !ok {
		available := make([]string, 0, len(gc.Profiles))
		for k := range gc.Profiles {
			available = append(available, k)
		}
		return nil, "", fmt.Errorf("profile %q not found (available: %v)", name, available)
	}

	return &profile, name, nil
}
