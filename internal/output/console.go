package output

import (
	"fmt"
	"strings"
	"time"

	"github.com/jasonlovesdoggo/dorker/internal/models"
)

// ConsoleFormatter formats findings for console output
type ConsoleFormatter struct{}

// NewConsoleFormatter creates a new console formatter
func NewConsoleFormatter() *ConsoleFormatter {
	return &ConsoleFormatter{}
}

// Format formats findings for console output
func (f *ConsoleFormatter) Format(findings []models.Finding, metadata map[string]interface{}) string {
	var builder strings.Builder

	// Print header
	builder.WriteString("\n")
	builder.WriteString("==========================================\n")
	builder.WriteString("   DORKER VULNERABILITY SCAN RESULTS     \n")
	builder.WriteString("==========================================\n\n")

	// Print metadata
	builder.WriteString(fmt.Sprintf("Target: %s\n", metadata["target"]))
	builder.WriteString(fmt.Sprintf("Mode: %s\n", metadata["mode"]))
	builder.WriteString(fmt.Sprintf("Scan Date: %s\n", metadata["timestamp"]))
	builder.WriteString(fmt.Sprintf("Duration: %s\n", metadata["duration"]))
	builder.WriteString(fmt.Sprintf("Total Findings: %d\n", metadata["findingCount"]))
	builder.WriteString("\n")

	// No findings
	if len(findings) == 0 {
		builder.WriteString("No vulnerabilities found.\n")
		return builder.String()
	}

	// Print findings
	for i, finding := range findings {
		builder.WriteString(fmt.Sprintf("FINDING #%d (Risk Score: %d, Confidence: %d%%)\n",
			i+1, finding.RiskScore, finding.ConfidenceScore))
		builder.WriteString(fmt.Sprintf("Pattern: %s (%s)\n", finding.Pattern.Name, finding.Pattern.Type))
		builder.WriteString(fmt.Sprintf("File: %s, Line: %d\n", finding.FilePath, finding.LineNumber))
		builder.WriteString(fmt.Sprintf("URL: %s\n", finding.URL))
		builder.WriteString("Matched Content:\n")
		builder.WriteString(fmt.Sprintf("    %s\n", strings.ReplaceAll(finding.MatchedContent, "\n", "\n    ")))

		if finding.Pattern.CWE != "" {
			builder.WriteString(fmt.Sprintf("Notes: %s (%s) - %s\n",
				finding.Pattern.CWE, finding.Pattern.Type, finding.Notes))
		} else {
			builder.WriteString(fmt.Sprintf("Notes: %s\n", finding.Notes))
		}

		builder.WriteString("\n")
	}

	// Print recommendations
	builder.WriteString("==========================================\n")
	builder.WriteString("RECOMMENDATIONS\n")
	builder.WriteString("==========================================\n\n")
	builder.WriteString("Remember to manually verify all findings before reporting.\n")
	builder.WriteString("False positives may occur based on code context.\n\n")
	builder.WriteString(fmt.Sprintf("Scan completed at %s\n",
		time.Now().Format("2006-01-02 15:04:05")))

	return builder.String()
}
