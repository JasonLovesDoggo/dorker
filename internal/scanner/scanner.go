package scanner

import (
	"github.com/jasonlovesdoggo/dorker/internal/models"
	"github.com/jasonlovesdoggo/dorker/internal/patterns"
	"github.com/jasonlovesdoggo/dorker/pkg/utils"
)

// Scanner defines the interface for scanning targets
type Scanner interface {
	Scan(target string, patterns []patterns.Pattern) ([]models.Finding, error)
}

// BaseScanner provides common functionality for scanners
type BaseScanner struct {
	logger *utils.Logger
}

// NewBaseScanner creates a new base scanner
func NewBaseScanner(logger *utils.Logger) *BaseScanner {
	return &BaseScanner{
		logger: logger,
	}
}

// MatchPattern checks if a file content matches a vulnerability pattern
func (s *BaseScanner) MatchPattern(filePath, content string, pattern patterns.Pattern) bool {
	// Check if the file path matches the pattern's file path pattern
	if pattern.FilePath != "" && !utils.PathMatches(filePath, pattern.FilePath) {
		return false
	}

	// Check if the content matches the pattern's regex
	matched, err := utils.RegexMatch(pattern.Regex, content)
	if err != nil {
		s.logger.Error("Failed to match regex:", err)
		return false
	}

	if !matched {
		return false
	}

	// Check for false positive patterns
	for _, fpPattern := range pattern.FalsePositivePatterns {
		fpMatched, err := utils.RegexMatch(fpPattern, content)
		if err != nil {
			s.logger.Error("Failed to match false positive regex:", err)
			continue
		}
		if fpMatched {
			return false
		}
	}

	return true
}
