package scanner

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/google/go-github/v48/github"
	"github.com/jasonlovesdoggo/dorker/internal/config"
	"github.com/jasonlovesdoggo/dorker/internal/models"
	"github.com/jasonlovesdoggo/dorker/internal/patterns"
	"github.com/jasonlovesdoggo/dorker/pkg/github"
	"github.com/jasonlovesdoggo/dorker/pkg/utils"
	"golang.org/x/oauth2"
)

// GitHubScanner scans GitHub repositories for vulnerabilities
type GitHubScanner struct {
	*BaseScanner
	client *github.Client
	config *config.Config
}

// NewGitHubScanner creates a new GitHub scanner
func NewGitHubScanner(cfg struct {
	Token       string `yaml:"token"`
	APIEndpoint string `yaml:"api_endpoint"`
	Timeout     int    `yaml:"timeout_seconds"`
	RateLimit   int    `yaml:"rate_limit_per_hour"`
}, logger *utils.Logger) (*GitHubScanner, error) {
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: cfg.Token},
	)
	tc := oauth2.NewClient(ctx, ts)
	client := github.NewClient(tc)

	return &GitHubScanner{
		BaseScanner: NewBaseScanner(logger),
		client:      client,
	}, nil
}

// Scan scans a GitHub repository for vulnerabilities
func (s *GitHubScanner) Scan(target string, patterns []patterns.Pattern) ([]models.Finding, error) {
	var findings []models.Finding

	// Parse owner and repo from target
	parts := strings.Split(target, "/")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid GitHub repository format, expected 'owner/repo'")
	}
	owner, repo := parts[0], parts[1]

	s.logger.Info(fmt.Sprintf("Scanning GitHub repository: %s/%s", owner, repo))

	// Get repository info
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(s.config.GitHub.Timeout)*time.Second)
	defer cancel()

	repoInfo, _, err := s.client.Repositories.Get(ctx, owner, repo)
	if err != nil {
		return nil, fmt.Errorf("failed to get repository info: %w", err)
	}

	s.logger.Info(fmt.Sprintf("Repository: %s, Stars: %d, Language: %s",
		repoInfo.GetFullName(), repoInfo.GetStargazersCount(), repoInfo.GetLanguage()))

	// Build search queries for each pattern
	for _, pattern := range patterns {
		// Only search with patterns applicable to the repository's primary language
		if pattern.Language != patterns.Any && !s.isLanguageMatch(string(pattern.Language), repoInfo.GetLanguage()) {
			continue
		}

		// Normalize the search query for GitHub
		searchQuery := fmt.Sprintf("%s in:file repo:%s/%s", pattern.Regex, owner, repo)
		if pattern.FilePath != "" {
			searchQuery += fmt.Sprintf(" path:%s", pattern.FilePath)
		}

		s.logger.Info(fmt.Sprintf("Searching with query: %s", searchQuery))

		// Search code
		result, _, err := s.client.Search.Code(ctx, searchQuery, &github.SearchOptions{
			ListOptions: github.ListOptions{
				PerPage: 30,
			},
		})

		if err != nil {
			s.logger.Error(fmt.Sprintf("Search failed for pattern %s: %v", pattern.ID, err))
			// Continue with next pattern on error
			continue
		}

		// Process results
		for _, item := range result.CodeResults {
			// Get file content
			fileContent, _, _, err := s.client.Repositories.GetContents(ctx, owner, repo, item.GetPath(), &github.RepositoryContentGetOptions{})
			if err != nil {
				s.logger.Error(fmt.Sprintf("Failed to get contents for %s: %v", item.GetPath(), err))
				continue
			}

			content, err := base64.StdEncoding.DecodeString(fileContent.GetContent())
			if err != nil {
				s.logger.Error(fmt.Sprintf("Failed to decode content for %s: %v", item.GetPath(), err))
				continue
			}

			// Check if the file content actually matches the pattern
			if s.MatchPattern(item.GetPath(), string(content), pattern) {
				finding := models.Finding{
					Pattern:        pattern,
					Repository:     repoInfo.GetFullName(),
					FilePath:       item.GetPath(),
					LineNumber:     s.findLineNumber(string(content), pattern.Regex),
					MatchedContent: s.extractMatchedContext(string(content), pattern.Regex),
					URL:            item.GetHTMLURL(),
					FoundAt:        time.Now(),
				}
				findings = append(findings, finding)
				s.logger.Info(fmt.Sprintf("Found potential vulnerability: %s in %s", pattern.Name, item.GetPath()))
			}
		}

		// Rate limit handling
		time.Sleep(time.Second) // Basic rate limiting
	}

	return findings, nil
}

// isLanguageMatch checks if the pattern language matches the repository language
func (s *GitHubScanner) isLanguageMatch(patternLanguage, repoLanguage string) bool {
	if patternLanguage == "" || strings.EqualFold(patternLanguage, "ANY") {
		return true
	}

	// Handle language aliases and variations
	patternLang := strings.ToLower(patternLanguage)
	repoLang := strings.ToLower(repoLanguage)

	switch patternLang {
	case "php":
		return repoLang == "php"
	case "nodejs", "node.js", "javascript", "js":
		return repoLang == "javascript" || repoLang == "typescript"
	case "dotnet", ".net", "csharp", "c#":
		return repoLang == "c#" || repoLang == "f#" || repoLang == "visual basic"
	case "go", "golang":
		return repoLang == "go"
	}

	return false
}

// findLineNumber finds the line number of the first match
func (s *GitHubScanner) findLineNumber(content, regex string) int {
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		matched, _ := utils.RegexMatch(regex, line)
		if matched {
			return i + 1
		}
	}
	return 0
}

// extractMatchedContext extracts a snippet of context around the matched pattern
func (s *GitHubScanner) extractMatchedContext(content, regex string) string {
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		matched, _ := utils.RegexMatch(regex, line)
		if matched {
			// Extract a few lines above and below for context
			start := max(0, i-2)
			end := min(len(lines), i+3)
			context := lines[start:end]
			return strings.Join(context, "\n")
		}
	}
	return ""
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
