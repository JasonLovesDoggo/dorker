package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jasonlovesdoggo/dorker/internal/analyzer"
	"github.com/jasonlovesdoggo/dorker/internal/config"
	"github.com/jasonlovesdoggo/dorker/internal/output"
	"github.com/jasonlovesdoggo/dorker/internal/scanner"
	"github.com/jasonlovesdoggo/dorker/pkg/utils"
)

func main() {
	// Parse command line flags
	configPath := flag.String("config", "configs/config.toml", "Path to configuration file")
	outputFormat := flag.String("output", "console", "Output format (console, json, html)")
	scanMode := flag.String("mode", "github", "Scan mode (github, local)")
	target := flag.String("target", "", "Target repository or directory")
	verbose := flag.Bool("verbose", false, "Enable verbose logging")
	flag.Parse()

	// Initialize logger
	logger := utils.NewLogger(*verbose)
	logger.Info("Dorker starting...")

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Fatal("Failed to load configuration:", err)
	}

	// Validate target
	if *target == "" {
		logger.Fatal("No target specified. Use --target flag to specify a target.", nil)
	}

	// Validate target format based on mode
	if *scanMode == "github" {
		if !strings.Contains(*target, "/") || len(strings.Split(*target, "/")) != 2 {
			logger.Fatal("Invalid GitHub repository format. Expected format: owner/repo", nil)
		}
	} else if *scanMode == "local" {
		if _, err := os.Stat(*target); os.IsNotExist(err) {
			logger.Fatal("Target directory does not exist", err)
		}
	}

	// Load vulnerability patterns
	vulnPatterns, err := config.LoadPatterns(cfg)
	if err != nil {
		logger.Fatal("Failed to load vulnerability patterns:", err)
	}
	logger.Info(fmt.Sprintf("Loaded %d vulnerability patterns", len(vulnPatterns)))

	// Initialize scanner based on mode
	var scannerInstance scanner.Scanner
	switch *scanMode {
	case "github":
		// Validate GitHub token
		if cfg.GitHub.Token == "" {
			logger.Fatal("GitHub token is required for GitHub scanning mode. Add it to your config.toml file.", nil)
		}
		scannerInstance, err = scanner.NewGitHubScanner(struct {
			Token       string
			APIEndpoint string
			Timeout     int
			RateLimit   int
		}(cfg.GitHub), logger)
	case "local":
		panic("local scanning mode not implemented yet")
		//scannerInstance, err = scanner.NewLocalScanner(logger)
	default:
		logger.Fatal("Unknown scan mode:", fmt.Errorf("mode %s not supported", *scanMode))
		return
	}

	if err != nil {
		logger.Fatal("Failed to initialize scanner:", err)
	}

	// Run the scan
	startTime := time.Now()
	logger.Info(fmt.Sprintf("Starting scan on target: %s", *target))
	findings, err := scannerInstance.Scan(*target, vulnPatterns)
	if err != nil {
		logger.Fatal("Scan failed:", err)
	}

	// Analyze findings
	analyzerInstance := analyzer.NewAnalyzer(logger)
	analyzedFindings := analyzerInstance.Analyze(findings)
	scanDuration := time.Since(startTime)

	// Generate report
	formatter, err := output.GetFormatter(*outputFormat)
	if err != nil {
		logger.Fatal("Failed to get output formatter:", err)
	}

	report := formatter.Format(analyzedFindings, map[string]interface{}{
		"target":       *target,
		"mode":         *scanMode,
		"duration":     scanDuration.String(),
		"timestamp":    time.Now().Format(time.RFC3339),
		"findingCount": len(analyzedFindings),
	})

	// Output report
	fmt.Println(report)
	logger.Info(fmt.Sprintf("Scan completed in %s. Found %d potential vulnerabilities.",
		scanDuration.String(), len(analyzedFindings)))
}
