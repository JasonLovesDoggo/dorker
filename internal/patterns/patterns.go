package patterns

// VulnerabilityType represents the type of vulnerability
type VulnerabilityType string

const (
	XSS                     VulnerabilityType = "XSS"
	SQLInjection            VulnerabilityType = "SQL_INJECTION"
	CommandInjection        VulnerabilityType = "COMMAND_INJECTION"
	PathTraversal           VulnerabilityType = "PATH_TRAVERSAL"
	InsecureDeserialization VulnerabilityType = "INSECURE_DESERIALIZATION"
	HostHeaderInjection     VulnerabilityType = "HOST_HEADER_INJECTION"
	SSRF                    VulnerabilityType = "SSRF"
	OpenRedirect            VulnerabilityType = "OPEN_REDIRECT"
)

// Language represents a programming language
type Language string

const (
	PHP    Language = "PHP"
	NodeJS Language = "NODEJS"
	DotNet Language = "DOTNET"
	Go     Language = "GO"
	Any    Language = "ANY"
)

// Pattern represents a vulnerability pattern to search for
type Pattern struct {
	ID                    string            `toml:"id"`
	Name                  string            `toml:"name"`
	Type                  VulnerabilityType `toml:"type"`
	Language              Language          `toml:"language"`
	Regex                 string            `toml:"regex"`
	FilePath              string            `toml:"file_path"`
	Description           string            `toml:"description"`
	Severity              string            `toml:"severity"`
	CWE                   string            `toml:"cwe"`
	FalsePositivePatterns []string          `toml:"false_positive_patterns"`
	ExampleURL            string            `toml:"example_url"`
}
