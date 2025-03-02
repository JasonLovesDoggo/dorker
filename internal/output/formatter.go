package output

import (
	"fmt"

	"github.com/jasonlovesdoggo/dorker/internal/models"
)

// Formatter defines the interface for output formatters
type Formatter interface {
	Format(findings []models.Finding, metadata map[string]interface{}) string
}

// GetFormatter returns an output formatter based on the format name
func GetFormatter(format string) (Formatter, error) {
	switch format {
	case "console":
		return NewConsoleFormatter(), nil
	case "json":
		return NewJSONFormatter(), nil
	case "html":
		return NewHTMLFormatter(), nil
	default:
		return nil, fmt.Errorf("unsupported output format: %s", format)
	}
}
