# Dorker - Automated Vulnerability Finding Tool

I'll update the code to reflect your project rename to "dorker" and fix the missing packages. Here's an updated README and the corrected structure for the missing components.

```markdown name=README.md
# Dorker

A modular, intelligent tool for discovering potential security vulnerabilities in source code repositories using GitHub dorks and pattern matching.

## Features

- Scan GitHub repositories or local codebases for security vulnerabilities
- Modular pattern-based vulnerability detection for multiple languages
- Customizable vulnerability patterns/dorks
- Risk scoring and confidence assessment
- Multiple output formats (console, JSON, HTML)
- Detailed reporting with links to vulnerable code
- Easy integration with CI/CD pipelines

## Installation

### Prerequisites

- Go 1.18 or newer
- GitHub API token (for scanning GitHub repositories)

### Building from source

```bash
git clone https://github.com/JasonLovesDoggo/dorker.git
cd dorker
go build -o dorker ./cmd/dorker
```

## Configuration

Dorker uses TOML for configuration. The main configuration file is located at `configs/config.toml`:

```toml
[github]
token = "your-github-token"
api_endpoint = "https://api.github.com"
timeout_seconds = 60
rate_limit_per_hour = 5000

patterns_dir = "configs/patterns"
output_dir = "reports"
max_results = 100
```

### GitHub API Token

For scanning GitHub repositories, you need a GitHub API token. You can create one at [https://github.com/settings/tokens](https://github.com/settings/tokens).

## Pattern Files

Vulnerability patterns (dorks) are defined in individual TOML files in the `configs/patterns` directory. Each file represents a specific vulnerability pattern:

```
configs/patterns/
├── php/
│   ├── xss_echo_get.toml
│   ├── xss_echo_request.toml
│   ├── sql_injection.toml
│   └── insecure_deserialization.toml
├── nodejs/
│   ├── host_header_injection.toml
│   └── ...
└── ...
```

### Sample Pattern File

Here's an example of a pattern file (`configs/patterns/php/xss_echo_get.toml`):

```toml
id = "PHP-XSS-001"
name = "PHP Echo with GET Parameter"
type = "XSS"
language = "PHP"
regex = "\\becho\\b.*\\$_GET\\b"
description = "PHP code that directly echoes GET parameters without sanitization"
severity = "high"
cwe = "CWE-79"
false_positive_patterns = [
    "htmlspecialchars\\(\\$_GET",
    "htmlentities\\(\\$_GET",
    "strip_tags\\(\\$_GET"
]
example_url = "https://github.com/msaad1999/PHP-Login-System/blob/master/includes/profile-card.inc.php"
```

## Usage

### Basic Usage

Scan a GitHub repository:

```bash
./dorker --mode github --target "msaad1999/PHP-Login-System"
```

Scan a local directory:

```bash
./dorker --mode local --target "/path/to/code"
```

### Advanced Options

```bash
./dorker --config custom-config.toml --output json --mode github --target "owner/repo" --verbose
```

- `--config`: Path to configuration file (default: `configs/config.toml`)
- `--output`: Output format - console, json, html (default: console)
- `--mode`: Scan mode - github, local (default: github)
- `--target`: Target repository (GitHub mode) or directory (local mode)
- `--verbose`: Enable verbose logging

## Adding Custom Patterns

To add your own vulnerability patterns:

1. Create a new TOML file in the appropriate language directory under `configs/patterns/`
2. Define the pattern using the format shown in the sample above
3. Restart Dorker to load the new pattern

## Example Output

```
Dorker starting...
Loaded 22 vulnerability patterns
Starting scan on target: msaad1999/PHP-Login-System
Found potential vulnerability: PHP Echo with GET Parameter in includes/profile-card.inc.php
Found potential vulnerability: PHP SQL Query with User Input in includes/dbh.inc.php
Scan completed in 1m12s. Found 2 potential vulnerabilities.

FINDING #1 (Risk Score: 85, Confidence: 92%)
Pattern: PHP SQL Query with User Input (SQL_INJECTION)
File: includes/dbh.inc.php, Line: 42
URL: https://github.com/msaad1999/PHP-Login-System/blob/master/includes/dbh.inc.php#L42
Matched Content:
    $sql = "SELECT * FROM users WHERE uidUsers='$username'";
    $result = mysqli_query($conn, $sql);
    $row = mysqli_fetch_assoc($result);
Notes: CWE-89 (SQL Injection) - Direct use of user input in SQL query without prepared statements.
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the GPLv3 License - see the LICENSE file for details.
