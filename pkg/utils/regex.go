package utils

import (
	"regexp"
	"strings"
)

// RegexMatch checks if content matches a regular expression
func RegexMatch(pattern, content string) (bool, error) {
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return false, err
	}
	return regex.MatchString(content), nil
}

// PathMatches checks if a file path matches a glob pattern
func PathMatches(path, pattern string) bool {
	// Convert glob pattern to regex
	// * matches any sequence of characters in the current directory
	// ** matches any sequence of characters across directories

	regexPattern := "^"

	// Escape special characters except * and **
	pattern = strings.Replace(pattern, ".", "\\.", -1)
	pattern = strings.Replace(pattern, "?", "\\?", -1)
	pattern = strings.Replace(pattern, "+", "\\+", -1)
	pattern = strings.Replace(pattern, "(", "\\(", -1)
	pattern = strings.Replace(pattern, ")", "\\)", -1)
	pattern = strings.Replace(pattern, "[", "\\[", -1)
	pattern = strings.Replace(pattern, "]", "\\]", -1)
	pattern = strings.Replace(pattern, "{", "\\{", -1)
	pattern = strings.Replace(pattern, "}", "\\}", -1)
	pattern = strings.Replace(pattern, "|", "\\|", -1)

	// Handle ** pattern (matches across directories)
	pattern = strings.Replace(pattern, "**", ".*", -1)

	// Handle * pattern (doesn't match directory separators)
	pattern = strings.Replace(pattern, "*", "[^/]*", -1)

	regexPattern += pattern + "$"

	matched, err := RegexMatch(regexPattern, path)
	if err != nil {
		return false
	}
	return matched
}

// ExtractContent extracts the matched content from a string based on a regular expression
func ExtractContent(content, pattern string, contextLines int) string {
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return ""
	}

	loc := regex.FindStringIndex(content)
	if loc == nil {
		return ""
	}

	// Find the line numbers
	lines := strings.Split(content, "\n")
	startIdx := loc[0]

	lineStart := 0
	startLine := 0
	for i, line := range lines {
		lineEnd := lineStart + len(line)
		if startIdx >= lineStart && startIdx <= lineEnd {
			startLine = i
			break
		}
		lineStart = lineEnd + 1 // +1 for the newline
	}

	// Extract context lines
	start := max(0, startLine-contextLines)
	end := min(len(lines), startLine+contextLines+1)
	contextContent := strings.Join(lines[start:end], "\n")

	return contextContent
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
