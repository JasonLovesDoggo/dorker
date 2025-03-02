package models

import (
	"time"

	"github.com/jasonlovesdoggo/dorker/internal/patterns"
)

// Finding represents a potential vulnerability finding
type Finding struct {
	Pattern         patterns.Pattern
	Repository      string
	FilePath        string
	LineNumber      int
	MatchedContent  string
	URL             string
	FoundAt         time.Time
	RiskScore       int
	ConfidenceScore int
	Notes           string
}
