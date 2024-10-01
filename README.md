# Comprehensive Code Collector CLI Tool

This tool traverses directories or clones GitHub repositories to collect and analyze code files. It offers features like secret detection, code metrics extraction, linting, formatting, and minification. All operations are performed on in-memory copies to ensure original files remain unaltered.

**Author:** Pranay Suyash
**License:** MIT

---

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Installation](#installation)
  - [Prerequisites](#prerequisites)
  - [Installing Dependencies](#installing-dependencies)
- [Usage](#usage)
  - [Command-Line Arguments](#command-line-arguments)
  - [Examples](#examples)
- [Configuration](#configuration)
  - [Configuration File](#configuration-file)
  - [Custom Secret Patterns](#custom-secret-patterns)
- [Output Formats](#output-formats)
- [Handling Secrets](#handling-secrets)
- [Examples](#examples-1)
- [Contributing](#contributing)
- [License](#license)

---

## Introduction

The Comprehensive Code Collector CLI Tool is designed to help developers and security professionals analyze codebases efficiently. It can traverse local directories or clone GitHub repositories, collecting code files based on specified criteria. The tool performs various analyses, such as secret detection, code metrics extraction, linting, formatting, and minification. Importantly, all operations are performed on in-memory copies to ensure the original files remain unaltered.

---

## Features

- **Directory Traversal or GitHub Cloning**: Analyze local directories or clone GitHub repositories for analysis.
- **File Inclusion/Exclusion**: Specify which file extensions or directories to include or exclude.
- **Comment Removal**: Optionally remove comments from code files.
- **Code Minification**: Minify code to reduce its size.
- **Code Formatting**: Format code using language-specific formatters (e.g., Black for Python).
- **Code Metrics Extraction**: Extract code metrics like Lines of Code (LOC), cyclomatic complexity, and maintainability index.
- **Secret Detection**: Detect potential secrets in code using predefined and custom regex patterns.
- **Secret Handling**: Choose to keep, redact, or remove detected secrets from the code.
- **Linting**: Run linters on code files to identify potential issues.
- **Security Misconfiguration Checks**: Identify common security misconfigurations in code files.
- **Directory Structure Tree**: Generate a visual tree of the directory structure.
- **Output Formats**: Export the analysis in Markdown, JSON, or plain text formats.
- **PDF Export**: Optionally export the Markdown report to PDF using Pandoc.
- **Asynchronous Processing**: Utilize asynchronous operations for efficient file reading.
- **Logging and Verbose Output**: Monitor the tool's progress with logging and optional verbose output.

---

## Installation

### Prerequisites

- **Python 3.6 or higher**: Ensure you have Python 3.6+ installed.
- **Git**: Required if you plan to clone GitHub repositories.
- **Pandoc**: Required if you want to export the report to PDF.
- **Node.js and npm**: Required for linting JavaScript/TypeScript files using ESLint and formatting with Prettier.

### Installing Dependencies

1. **Clone the Repository**

   ```bash
   git clone https://github.com/yourusername/code-collector-cli.git
   cd code-collector-cli
   ```

2. **Install Python Dependencies**

   It's recommended to use a virtual environment:

   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   pip install -r requirements.txt
   ```

   **Note**: The `requirements.txt` file should contain all the necessary Python packages, such as `radon`, `PyYAML`, `tqdm`, `GitPython`, etc.

3. **Install Node.js Packages (Optional)**

   If you plan to format or lint JavaScript/TypeScript files:

   ```bash
   npm install -g eslint prettier
   ```

4. **Install Pandoc (Optional)**

   If you want to export the Markdown report to PDF:

   - On Ubuntu/Debian:

     ```bash
     sudo apt-get install pandoc
     ```

   - On macOS using Homebrew:

     ```bash
     brew install pandoc
     ```

   - For other systems, refer to the [Pandoc installation guide](https://pandoc.org/installing.html).

---

## Usage

You can run the tool using the Python interpreter:

```bash
python3 code_collector.py [options]
```

### Command-Line Arguments

- **Positional Arguments:**
  - `directory`: Path of the folder to traverse.

- **Optional Arguments:**

  - `-h`, `--help`: Show the help message and exit.
  - `-o`, `--output`: Output file name without extension (default: `collected_code`).
  - `--config`: Path to configuration file (YAML or JSON).
  - `--include-extensions`: Comma-separated list of extensions to include (overrides config).
  - `--exclude-extensions`: Comma-separated list of extensions to exclude (overrides config).
  - `--include-dirs`: Comma-separated list of directories to include (overrides config).
  - `--exclude-dirs`: Comma-separated list of directories to exclude (overrides config).
  - `--remove-comments`: Remove comments from the code (overrides config).
  - `--minify`: Minify the code (overrides config).
  - `--format-code`: Format code using formatters (overrides config).
  - `--github`: GitHub repository URL to clone and process.
  - `--branch`: Branch to clone from GitHub repo (default: `main`).
  - `--output-format`: Output format (`markdown`, `json`, or `text`; default: `markdown`).
  - `--export-pdf`: Export Markdown output to PDF.
  - `--verbose`: Enable verbose logging.
  - `--extract-metrics`: Extract code metrics (LOC, cyclomatic complexity).
  - `--detect-secrets`: Detect potential secrets in code.
  - `--handle-secrets`: Handle detected secrets: `keep`, `redact`, or `remove` (default: `keep`).
  - `--run-linter`: Run linters on code files.
  - `--custom-secret-patterns`: Path to a file containing custom regex patterns for secret detection (one per line).

### Examples

1. **Traverse a Local Directory and Generate a Markdown Report**

   ```bash
   python3 code_collector.py ./my_project -o report --extract-metrics --detect-secrets --run-linter
   ```

2. **Clone a GitHub Repository and Analyze It**

   ```bash
   python3 code_collector.py . --github https://github.com/user/repo.git --branch main --output-format json --minify
   ```

3. **Use a Configuration File**

   ```bash
   python3 code_collector.py ./my_project --config config.yaml
   ```

4. **Export the Report to PDF**

   ```bash
   python3 code_collector.py ./my_project --export-pdf
   ```

5. **Include Only Specific File Extensions**

   ```bash
   python3 code_collector.py ./my_project --include-extensions .py,.js --exclude-dirs tests,docs
   ```

6. **Handle Secrets by Redacting Them**

   ```bash
   python3 code_collector.py ./my_project --detect-secrets --handle-secrets redact
   ```

---

## Configuration

### Configuration File

You can specify a YAML or JSON configuration file to set default options:

**Example `config.yaml`:**

```yaml
include_extensions:
  - .py
  - .js
exclude_dirs:
  - tests
  - docs
remove_comments: true
minify: false
format_code: true
extract_metrics: true
detect_secrets: true
handle_secrets: redact
run_linter: true
custom_secret_patterns:
  - 'secret_[A-Za-z0-9]+'
```

**Using the Configuration File:**

```bash
python3 code_collector.py ./my_project --config config.yaml
```

### Custom Secret Patterns

If you need to detect custom secret patterns, you can provide a file containing regex patterns (one per line).

**Example `custom_patterns.txt`:**

```
custom_api_key_[A-Za-z0-9]{32}
private_token_[A-Za-z0-9]{40}
```

**Using Custom Secret Patterns:**

```bash
python3 code_collector.py ./my_project --detect-secrets --custom-secret-patterns custom_patterns.txt
```

---

## Output Formats

The tool supports exporting the analysis in three formats:

1. **Markdown** (`--output-format markdown`): Generates a detailed Markdown report, suitable for reading or converting to PDF.

2. **JSON** (`--output-format json`): Exports data in JSON format, useful for further processing or integration with other tools.

3. **Plain Text** (`--output-format text`): Outputs a simple text report.

**Example: Generate a JSON Report**

```bash
python3 code_collector.py ./my_project --output-format json -o analysis_report
```

---

## Handling Secrets

When the `--detect-secrets` option is enabled, the tool scans code files for potential secrets using predefined and custom regex patterns.

You can specify how to handle detected secrets using the `--handle-secrets` option:

- `keep`: Leave the secrets in the code (default behavior).
- `redact`: Replace the secrets with `REDACTED` in the output.
- `remove`: Remove the secrets entirely from the code in the output.

**Example: Redact Secrets**

```bash
python3 code_collector.py ./my_project --detect-secrets --handle-secrets redact
```

---

## Examples

### Example 1: Basic Usage

Analyze a local directory and generate a Markdown report with default settings.

```bash
python3 code_collector.py ./my_project
```

### Example 2: Verbose Output with Metrics and Linting

Analyze a directory, extract code metrics, run linters, and enable verbose logging.

```bash
python3 code_collector.py ./my_project --extract-metrics --run-linter --verbose
```

### Example 3: Clone a GitHub Repository and Export to PDF

Clone a repository, detect secrets, handle them by removing, and export the report to PDF.

```bash
python3 code_collector.py . --github https://github.com/user/repo.git --detect-secrets --handle-secrets remove --export-pdf
```

### Example 4: Exclude Specific Extensions and Directories

Analyze code while excluding certain file types and directories.

```bash
python3 code_collector.py ./my_project --exclude-extensions .md,.txt --exclude-dirs tests,docs
```

---

## Contributing

Contributions are welcome! Please submit a pull request or open an issue to discuss improvements, features, or bugs.

1. Fork the repository.
2. Create a new branch for your feature or bugfix.
3. Commit your changes with clear messages.
4. Push your branch and open a pull request.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Detailed Feature Descriptions

### Directory Traversal and GitHub Cloning

- **Local Directory Analysis**: Provide a path to a local directory, and the tool will recursively traverse and analyze code files.
- **GitHub Repository Cloning**: Use the `--github` option to specify a GitHub repository URL. The tool will clone the repository into a temporary directory for analysis.
- **Branch Selection**: Use the `--branch` option to specify a branch other than `main`.

### File Inclusion and Exclusion

- **Include Extensions**: Use `--include-extensions` to specify which file types to include (e.g., `.py`, `.js`).
- **Exclude Extensions**: Use `--exclude-extensions` to exclude certain file types.
- **Include Directories**: Use `--include-dirs` to only include specific directories.
- **Exclude Directories**: Use `--exclude-dirs` to exclude specific directories (e.g., `node_modules`, `tests`).

### Comment Removal

- **Purpose**: Remove comments from code files to reduce noise or for compliance reasons.
- **Usage**: Enable with `--remove-comments`.
- **Supported Languages**: Handles comment removal for languages like Python, JavaScript/TypeScript, HTML, and CSS.

### Code Minification

- **Purpose**: Minify code to reduce its size, useful for preparing code snippets or reports.
- **Usage**: Enable with `--minify`.
- **Supported Languages**:
  - **JavaScript/TypeScript**: Removes whitespace and comments.
  - **CSS**: Minifies using `cssmin` if available.
  - **HTML**: Minifies using `htmlmin` if available.
  - **Python**: Basic minification by removing blank lines and comments.

### Code Formatting

- **Purpose**: Format code using standard formatters to improve readability.
- **Usage**: Enable with `--format-code`.
- **Supported Languages**:
  - **Python**: Uses `black` for formatting.
  - **JavaScript/TypeScript/CSS/HTML**: Uses `prettier` if installed.

### Code Metrics Extraction

- **Purpose**: Extract useful code metrics for analysis.
- **Usage**: Enable with `--extract-metrics`.
- **Metrics Extracted**:
  - **Python**: Lines of Code (LOC), Source Lines of Code (SLOC), Cyclomatic Complexity, Maintainability Index, etc., using `radon`.
  - **JavaScript/TypeScript**: Basic metrics like LOC and SLOC.

### Secret Detection

- **Purpose**: Identify potential secrets in the code to prevent leaks.
- **Usage**: Enable with `--detect-secrets`.
- **Secret Handling**: Specify how to handle detected secrets with `--handle-secrets` (`keep`, `redact`, `remove`).
- **Predefined Patterns**: Includes patterns for AWS keys, Google API keys, GitHub tokens, and more.
- **Custom Patterns**: Provide custom regex patterns via a file using `--custom-secret-patterns`.

### Linting

- **Purpose**: Run linters on code files to identify syntax errors and code quality issues.
- **Usage**: Enable with `--run-linter`.
- **Supported Linters**:
  - **Python**: Uses `flake8`.
  - **JavaScript/TypeScript**: Uses `eslint`.

### Security Misconfiguration Checks

- **Purpose**: Detect common security misconfigurations in code files.
- **Checks Performed**:
  - **package.json**: Checks for unpinned dependencies.
  - **Python Files**: Looks for the use of unsafe functions like `eval` and `exec`.
  - **JavaScript Files**: Detects the use of `eval()`.

### Directory Structure Tree

- **Purpose**: Generate a visual tree of the directory structure.
- **Usage**: Automatically included in the output.
- **Example Output**:

  ```
  ├── src/
  │   ├── main.py
  │   └── utils.py
  ├── tests/
  │   └── test_main.py
  └── README.md
  ```

### Output Formats

- **Markdown**: Detailed report with code snippets, metrics, and analysis.
- **JSON**: Structured data suitable for automation or further processing.
- **Plain Text**: Simple text output.

### PDF Export

- **Purpose**: Generate a PDF report from the Markdown output.
- **Usage**: Enable with `--export-pdf` (requires Pandoc).
- **Example**:

  ```bash
  python3 code_collector.py ./my_project --export-pdf
  ```

### Asynchronous Processing

- **Purpose**: Improve performance by reading files asynchronously.
- **Implementation**: Uses `asyncio` for asynchronous file I/O operations.

### Logging and Verbose Output

- **Purpose**: Monitor the tool's progress and debug issues.
- **Usage**: Enable verbose logging with `--verbose`.
- **Logging Levels**: Info and debug messages are displayed based on the logging level.

---

## Notes and Limitations

- **File Encoding**: Assumes files are encoded in UTF-8. Files with different encodings may cause errors.
- **Language Support**: While the tool supports many programming languages for basic operations, advanced features like linting and formatting are limited to certain languages.
- **External Tools**: Some features rely on external tools (e.g., `black`, `eslint`, `prettier`). Ensure these are installed if you plan to use those features.
- **Pandoc for PDF Export**: PDF export requires Pandoc to be installed and may require LaTeX for complex documents.

---

## Conclusion

The Comprehensive Code Collector CLI Tool is a versatile utility for developers, security analysts, and anyone needing to analyze codebases. By providing a rich set of features and customization options, it helps in identifying potential issues, enforcing code quality, and generating comprehensive reports.

## New Feature: GUI Folder Selection

In addition to the command-line arguments, this version includes a GUI-based folder selection option. If no directory is specified in the command-line arguments, a GUI window will prompt you to select the desired folder.

### How to Use the GUI Feature
1. Run the script without specifying the directory argument:

   ```bash
   python codecv3.py
   ```

2. A folder selection dialog will appear. Choose the folder you want to analyze.

3. The rest of the options (e.g., removing comments, minification, output format) can still be used as command-line arguments.

### Example
```bash
python codecv3.py --remove-comments --output collected_code_gui
```

This command will open a GUI dialog to select the folder and generate the output with comments removed.

