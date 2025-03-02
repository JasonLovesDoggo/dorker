package config

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
	"github.com/jasonlovesdoggo/dorker/internal/patterns"
)

// Config holds the application configuration
type Config struct {
	GitHub struct {
		Token       string `toml:"token"`
		APIEndpoint string `toml:"api_endpoint"`
		Timeout     int    `toml:"timeout_seconds"`
		RateLimit   int    `toml:"rate_limit_per_hour"`
	} `toml:"github"`
	PatternsDir string `toml:"patterns_dir"`
	OutputDir   string `toml:"output_dir"`
	MaxResults  int    `toml:"max_results"`
}

// Load loads configuration from the specified TOML file
func Load(path string) (*Config, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	err = toml.Unmarshal(data, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Set defaults if not specified
	if config.GitHub.APIEndpoint == "" {
		config.GitHub.APIEndpoint = "https://api.github.com"
	}
	if config.GitHub.Timeout == 0 {
		config.GitHub.Timeout = 60
	}
	if config.GitHub.RateLimit == 0 {
		config.GitHub.RateLimit = 5000
	}
	if config.PatternsDir == "" {
		config.PatternsDir = "configs/patterns"
	}
	if config.MaxResults == 0 {
		config.MaxResults = 100
	}

	return &config, nil
}

// LoadPatterns loads all vulnerability patterns from individual files in the patterns directory
func LoadPatterns(config *Config) ([]patterns.Pattern, error) {
	var allPatterns []patterns.Pattern

	// Walk through the patterns directory
	err := filepath.Walk(config.PatternsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories and non-TOML files
		if info.IsDir() || filepath.Ext(path) != ".toml" {
			return nil
		}

		// Read and parse pattern file
		data, err := ioutil.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read pattern file %s: %w", path, err)
		}

		var pattern patterns.Pattern
		err = toml.Unmarshal(data, &pattern)
		if err != nil {
			return fmt.Errorf("failed to parse pattern file %s: %w", path, err)
		}

		allPatterns = append(allPatterns, pattern)
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to load patterns: %w", err)
	}

	return allPatterns, nil
}
