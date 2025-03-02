package analyzer

import (
	"fmt"
	"sort"
	"strings"

	"github.com/jasonlovesdoggo/dorker/internal/models"
	"github.com/jasonlovesdoggo/dorker/pkg/utils"
)

// Analyzer analyzes findings and calculates risk scores
type Analyzer struct {
	logger *utils.Logger
}

// NewAnalyzer creates a new analyzer
func NewAnalyzer(logger *utils.Logger) *Analyzer {
	return &Analyzer{
		logger: logger,
	}
}

// Analyze analyzes findings and enriches them with risk scores and additional data
func (a *Analyzer) Analyze(findings []models.Finding) []models.Finding {
	var analyzedFindings []models.Finding

	for _, finding := range findings {
		// Calculate risk score
		riskScore := a.calculateRiskScore(finding)
		finding.RiskScore = riskScore

		// Calculate confidence score
		confidenceScore := a.calculateConfidenceScore(finding)
		finding.ConfidenceScore = confidenceScore

		// Add analysis notes
		finding.Notes = a.generateNotes(finding)

		analyzedFindings = append(analyzedFindings, finding)
	}

	// Sort findings by risk score (highest first)
	a.sortFindingsByRisk(analyzedFindings)

	return analyzedFindings
}

// calculateRiskScore calculates the risk score of a finding
func (a *Analyzer) calculateRiskScore(finding models.Finding) int {
	score := 0

	// Base score based on severity
	switch strings.ToLower(finding.Pattern.Severity) {
	case "critical":
		score += 40
	case "high":
		score += 30
	case "medium":
		score += 20
	case "low":
		score += 10
	default:
		score += 5
	}

	// Additional risk factors

	// Vulnerability type factors
	switch finding.Pattern.Type {
	case "SQL_INJECTION", "COMMAND_INJECTION", "INSECURE_DESERIALIZATION":
		score += 15
	case "XSS", "HOST_HEADER_INJECTION":
		score += 10
	case "PATH_TRAVERSAL", "SSRF":
		score += 8
	case "OPEN_REDIRECT":
		score += 5
	}

	// Check for sensitive paths or functions
	lowerPath := strings.ToLower(finding.FilePath)
	lowerContent := strings.ToLower(finding.MatchedContent)

	if strings.Contains(lowerPath, "admin") ||
		strings.Contains(lowerPath, "auth") ||
		strings.Contains(lowerPath, "login") ||
		strings.Contains(lowerPath, "user") {
		score += 5
	}

	if strings.Contains(lowerContent, "password") ||
		strings.Contains(lowerContent, "token") ||
		strings.Contains(lowerContent, "secret") ||
		strings.Contains(lowerContent, "key") {
		score += 8
	}

	return score
}

// calculateConfidenceScore calculates how confident we are in the finding
func (a *Analyzer) calculateConfidenceScore(finding models.Finding) int {
	score := 50 // Start with a neutral score

	// Precise regex patterns increase confidence
	if strings.Contains(finding.Pattern.Regex, "\\b") {
		score += 10
	}

	// Check for sanitization functions that might reduce likelihood
	lowerContent := strings.ToLower(finding.MatchedContent)
	if strings.Contains(lowerContent, "sanitize") ||
		strings.Contains(lowerContent, "escape") ||
		strings.Contains(lowerContent, "filter") {
		score -= 15
	}

	// Examples in the pattern increase confidence
	if finding.Pattern.ExampleURL != "" {
		score += 5
	}

	// Patterns with false positive checks are more reliable
	if len(finding.Pattern.FalsePositivePatterns) > 0 {
		score += len(finding.Pattern.FalsePositivePatterns) * 3
	}

	// Clamp score between 0 and 100
	if score < 0 {
		score = 0
	} else if score > 100 {
		score = 100
	}

	return score
}

// generateNotes generates analysis notes for the finding
func (a *Analyzer) generateNotes(finding models.Finding) string {
	var notes []string

	// Add CWE reference if available
	if finding.Pattern.CWE != "" {
		notes = append(notes, fmt.Sprintf("%s - vulnerability type identified", finding.Pattern.CWE))
	}

	// Add notes based on vulnerability type
	switch finding.Pattern.Type {
	case "SQL_INJECTION":
		notes = append(notes, "Direct use of user input in SQL query without prepared statements")
	case "XSS":
		notes = append(notes, "User input directly output to HTML without sanitization")
	case "COMMAND_INJECTION":
		notes = append(notes, "User input passed directly to command execution functions")
	case "INSECURE_DESERIALIZATION":
		notes = append(notes, "User input deserialized without validation")
	case "HOST_HEADER_INJECTION":
		notes = append(notes, "Host header used in sensitive functionality like password reset")
	case "SSRF":
		notes = append(notes, "User input used in server-side request functions")
	case "PATH_TRAVERSAL":
		notes = append(notes, "User input used in file path operations without sanitization")
	case "OPEN_REDIRECT":
		notes = append(notes, "User input used in redirection without validation")
	}

	// Add confidence note
	if finding.ConfidenceScore < 40 {
		notes = append(notes, "Low confidence detection, significant chance of false positive")
	} else if finding.ConfidenceScore > 80 {
		notes = append(notes, "High confidence detection, likely a true vulnerability")
	}

	return strings.Join(notes, ". ")
}

// sortFindingsByRisk sorts findings by risk score in descending order
func (a *Analyzer) sortFindingsByRisk(findings []models.Finding) {
	sort.Slice(findings, func(i, j int) bool {
		// Primary sort by risk score (descending)
		if findings[i].RiskScore != findings[j].RiskScore {
			return findings[i].RiskScore > findings[j].RiskScore
		}

		// Secondary sort by confidence score (descending)
		if findings[i].ConfidenceScore != findings[j].ConfidenceScore {
			return findings[i].ConfidenceScore > findings[j].ConfidenceScore
		}

		// Tertiary sort by severity (alphabetically, so "critical" comes before "high")
		return findings[i].Pattern.Severity < findings[j].Pattern.Severity
	})
}

// GetTopRisks returns the top N most risky findings
func (a *Analyzer) GetTopRisks(findings []models.Finding, n int) []models.Finding {
	if len(findings) <= n {
		return findings
	}
	return findings[:n]
}

// GetStatistics returns statistics about the findings
func (a *Analyzer) GetStatistics(findings []models.Finding) map[string]interface{} {
	stats := make(map[string]interface{})

	// Count by vulnerability type
	typeCount := make(map[string]int)
	for _, finding := range findings {
		typeCount[string(finding.Pattern.Type)]++
	}
	stats["typeCount"] = typeCount

	// Count by severity
	severityCount := make(map[string]int)
	for _, finding := range findings {
		severityCount[finding.Pattern.Severity]++
	}
	stats["severityCount"] = severityCount

	// Calculate average risk score
	totalRisk := 0
	for _, finding := range findings {
		totalRisk += finding.RiskScore
	}

	if len(findings) > 0 {
		stats["averageRiskScore"] = totalRisk / len(findings)
	} else {
		stats["averageRiskScore"] = 0
	}

	// Calculate highest risk score
	highestRisk := 0
	for _, finding := range findings {
		if finding.RiskScore > highestRisk {
			highestRisk = finding.RiskScore
		}
	}
	stats["highestRiskScore"] = highestRisk

	return stats
}
