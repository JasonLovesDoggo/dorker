package output

import (
	"fmt"
	"github.com/
	"html"
	"os"
	"strings"
	"time"
	"github.com/pkg/browser"

// HTMLFormatter formats findings for HTML output
type HTMLFormatter struct{}

// NewHTMLFormatter creates a new HTML formatter
func NewHTMLFormatter() *HTMLFormatter {
	return &HTMLFormatter{}
}

// Format formats findings for HTML output
func (f *HTMLFormatter) Format(findings []models.Finding, metadata map[string]interface{}) string {
	var builder strings.Builder

	// HTML header
	builder.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dorker Vulnerability Scan Results</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
        }
        h1, h2, h3 {
            color: #2c3e50;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        .header {
            background-color: #2c3e50;
            color: white;
            padding: 1rem;
            margin-bottom: 1rem;
            border-radius: 5px;
        }
        .metadata {
            background-color: #f8f9fa;
            padding: 1rem;
            border-radius: 5px;
            margin-bottom: 2rem;
        }
        .finding {
            background-color: #fff;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 1rem;
            margin-bottom: 1rem;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .finding-header {
            display: flex;
            justify-content: space-between;
            border-bottom: 1px solid #eee;
            padding-bottom: 0.5rem;
            margin-bottom: 1rem;
        }
        .high-risk {
            border-left: 5px solid #e74c3c;
        }
        .medium-risk {
            border-left: 5px solid #f39c12;
        }
        .low-risk {
            border-left: 5px solid #2ecc71;
        }
        .code {
            background-color: #f8f9fa;
            padding: 1rem;
            border-radius: 5px;
            border: 1px solid #ddd;
            font-family: monospace;
            white-space: pre-wrap;
            margin: 1rem 0;
        }
        .recommendations {
            background-color: #e8f4f8;
            padding: 1rem;
            border-radius: 5px;
            margin-top: 2rem;
        }
        .risk-badge {
            display: inline-block;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.8rem;
            color: white;
        }
        .risk-high {
            background-color: #e74c3c;
        }
        .risk-medium {
            background-color: #f39c12;
        }
        .risk-low {
            background-color: #2ecc71;
        }
        .footer {
            margin-top: 2rem;
            text-align: center;
            font-size: 0.9rem;
            color: #7f8c8d;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Dorker Vulnerability Scan Results</h1>
        </div>`)

	// Metadata section
	builder.WriteString(`
        <div class="metadata">
            <h2>Scan Information</h2>
            <p><strong>Target:</strong> ` + html.EscapeString(metadata["target"].(string)) + `</p>
            <p><strong>Mode:</strong> ` + html.EscapeString(metadata["mode"].(string)) + `</p>
            <p><strong>Scan Date:</strong> ` + html.EscapeString(metadata["timestamp"].(string)) + `</p>
            <p><strong>Duration:</strong> ` + html.EscapeString(metadata["duration"].(string)) + `</p>
            <p><strong>Total Findings:</strong> ` + fmt.Sprintf("%d", metadata["findingCount"].(int)) + `</p>
        </div>`)

	// No findings
	if len(findings) == 0 {
		builder.WriteString(`
        <div class="finding low-risk">
            <h2>No vulnerabilities found</h2>
            <p>The scan did not identify any potential vulnerabilities in the target.</p>
        </div>`)
	} else {
		// Findings section
		builder.WriteString(`
        <h2>Findings</h2>`)

		for i, finding := range findings {
			// Determine risk class based on risk score
			riskClass := "low-risk"
			riskBadge := "risk-low"
			if finding.RiskScore >= 70 {
				riskClass = "high-risk"
				riskBadge = "risk-high"
			} else if finding.RiskScore >= 30 {
				riskClass = "medium-risk"
				riskBadge = "risk-medium"
			}

			builder.WriteString(`
        <div class="finding ` + riskClass + `">
            <div class="finding-header">
                <h3>Finding #` + fmt.Sprintf("%d", i+1) + `: ` + html.EscapeString(finding.Pattern.Name) + `</h3>
                <span class="risk-badge ` + riskBadge + `">Risk Score: ` + fmt.Sprintf("%d", finding.RiskScore) + ` | Confidence: ` + fmt.Sprintf("%d%%", finding.ConfidenceScore) + `</span>
            </div>
            <p><strong>Type:</strong> ` + html.EscapeString(string(finding.Pattern.Type)) + `</p>
            <p><strong>File:</strong> ` + html.EscapeString(finding.FilePath) + `, Line: ` + fmt.Sprintf("%d", finding.LineNumber) + `</p>
            <p><strong>URL:</strong> <a href="` + html.EscapeString(finding.URL) + `" target="_blank">` + html.EscapeString(finding.URL) + `</a></p>
            <p><strong>Matched Content:</strong></p>
            <div class="code">` + html.EscapeString(finding.MatchedContent) + `</div>`)

			if finding.Pattern.CWE != "" {
				builder.WriteString(`
            <p><strong>CWE:</strong> ` + html.EscapeString(finding.Pattern.CWE) + `</p>`)
			}

			builder.WriteString(`
            <p><strong>Description:</strong> ` + html.EscapeString(finding.Pattern.Description) + `</p>
            <p><strong>Notes:</strong> ` + html.EscapeString(finding.Notes) + `</p>
        </div>`)
		}
	}

	// Recommendations section
	builder.WriteString(`
        <div class="recommendations">
            <h2>Recommendations</h2>
            <p>Remember to manually verify all findings before reporting. False positives may occur based on code context.</p>
            <ul>
                <li>Review each finding and confirm exploitability</li>
                <li>Prioritize fixes based on risk score and business impact</li>
                <li>Consider implementing secure coding practices and training</li>
                <li>Run scans regularly as part of your security testing process</li>
            </ul>
        </div>
        
        <div class="footer">
            <p>Generated by <a href="https://github.com/JasonLovesDoggo/dorker" target="_blank">Dorker</a> on ` + time.
		Now().
		Format("2006-01-02 15:04:05") + `</p>
        </div>
    </div>
</body>
</html>`)

	err := os.WriteFile("output.html", []byte(builder.String()), 0644)
	if err != nil {
		return ""
	}
	// Open the file in the default browser
	err = browser.OpenFile("output.html")
	return builder.String()
}
