package output

import (
	"encoding/json"
	"time"

	"github.com/jasonlovesdoggo/dorker/internal/models"
)

// JSONFormatter formats findings for JSON output
type JSONFormatter struct{}

// NewJSONFormatter creates a new JSON formatter
func NewJSONFormatter() *JSONFormatter {
	return &JSONFormatter{}
}

// JSONOutput represents the structure of JSON output
type JSONOutput struct {
	Metadata struct {
		Target       string    `json:"target"`
		Mode         string    `json:"mode"`
		ScanDate     time.Time `json:"scan_date"`
		Duration     string    `json:"duration"`
		FindingCount int       `json:"finding_count"`
	} `json:"metadata"`
	Findings []JSONFinding `json:"findings"`
}

// JSONFinding represents a finding in JSON format
type JSONFinding struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Type            string `json:"type"`
	FilePath        string `json:"file_path"`
	LineNumber      int    `json:"line_number"`
	MatchedContent  string `json:"matched_content"`
	URL             string `json:"url"`
	RiskScore       int    `json:"risk_score"`
	ConfidenceScore int    `json:"confidence_score"`
	CWE             string `json:"cwe,omitempty"`
	Description     string `json:"description"`
	Notes           string `json:"notes"`
}

// Format formats findings for JSON output
func (f *JSONFormatter) Format(findings []models.Finding, metadata map[string]interface{}) string {
	output := JSONOutput{}

	// Set metadata
	output.Metadata.Target = metadata["target"].(string)
	output.Metadata.Mode = metadata["mode"].(string)
	timestamp, _ := time.Parse(time.RFC3339, metadata["timestamp"].(string))
	output.Metadata.ScanDate = timestamp
	output.Metadata.Duration = metadata["duration"].(string)
	output.Metadata.FindingCount = metadata["findingCount"].(int)

	// Convert findings
	for _, finding := range findings {
		jsonFinding := JSONFinding{
			ID:              finding.Pattern.ID,
			Name:            finding.Pattern.Name,
			Type:            string(finding.Pattern.Type),
			FilePath:        finding.FilePath,
			LineNumber:      finding.LineNumber,
			MatchedContent:  finding.MatchedContent,
			URL:             finding.URL,
			RiskScore:       finding.RiskScore,
			ConfidenceScore: finding.ConfidenceScore,
			CWE:             finding.Pattern.CWE,
			Description:     finding.Pattern.Description,
			Notes:           finding.Notes,
		}
		output.Findings = append(output.Findings, jsonFinding)
	}

	// Convert to JSON
	jsonBytes, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return `{"error": "Failed to generate JSON output"}`
	}

	return string(jsonBytes)
}
