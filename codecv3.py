#!/usr/bin/env python3
"""
Comprehensive Code Collector CLI Tool

This tool traverses directories or clones GitHub repositories to collect and analyze code files.
It offers features like secret detection, code metrics extraction, linting, formatting, and minification.
All operations are performed on in-memory copies to ensure original files remain unaltered.

Author: Your Name
License: MIT
"""

import os
import sys
import json
import argparse
import re
import logging
import asyncio
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional
import datetime

import yaml
from tqdm import tqdm
from git import Repo
from radon.complexity import cc_visit
from radon.metrics import mi_visit
from radon.raw import analyze as radon_raw_analyze

# Initialize logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='%(message)s')

# List of programming file extensions
PROGRAMMING_EXTENSIONS = [
    '.py', '.ipynb', '.js', '.jsx', '.ts', '.tsx', '.html', '.css', '.java', '.c', '.cpp', '.h',
    '.cs', '.rb', '.php', '.go', '.rs', '.swift', '.kt', '.scala', '.pl', '.lua', '.r', '.sql',
    '.sh', '.bat', '.m', '.vb', '.erl', '.ex', '.clj', '.hs', '.s', '.asm', '.ps1', '.groovy',
    '.f', '.f90', '.lisp', '.lsp', '.fs', '.ml', '.jl', '.env', '.json5', '.toml', '.xml', '.ini'
]

# Default excluded directories
DEFAULT_EXCLUDE_DIRS = {'.git', 'node_modules', '__pycache__', 'dist'}

# Supported output formats
OUTPUT_FORMATS = ['markdown', 'json', 'text']

# Security Patterns
SECRET_PATTERNS = [
    r'AKIA[0-9A-Z]{16}',  # AWS Access Key
    r'AIza[0-9A-Za-z-_]{35}',  # Google API Key
    r'ghp_[0-9a-zA-Z]{36}',  # GitHub Personal Access Token
    r'sk_live_[0-9a-zA-Z]{24}',  # Stripe Secret Key
    r'rk_live_[0-9a-zA-Z]{24}',  # Stripe Restricted Key
    r'sq0csp-[0-9A-Za-z-_]{43}',  # Square Access Token
    r'SK[0-9a-fA-F]{32}',  # Twilio API Key
    r'SG\.[0-9A-Za-z-_]{22}\.[0-9A-Za-z-_]{43}',  # SendGrid API Key
    r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',  # Google OAuth
    r'-----BEGIN RSA PRIVATE KEY-----',  # RSA private key
    r'-----BEGIN OPENSSH PRIVATE KEY-----',  # OpenSSH private key
    r'-----BEGIN PGP PRIVATE KEY BLOCK-----',  # PGP private key
    r'mysql://[^:]+:[^@]+@[^/]+/\w+',  # MySQL connection string
    r'postgres://[^:]+:[^@]+@[^/]+/\w+',  # PostgreSQL connection string
]

# Patterns for .env files (variables ending with KEY, SECRET, PASSWORD, etc.)
ENV_SECRET_VARIABLE_PATTERN = re.compile(r'^(?P<var>.*(?:KEY|SECRET|PASSWORD|TOKEN))=(?P<val>.*)$', re.IGNORECASE)

def check_required_packages():
    try:
        import radon
        import yaml
        import tqdm
        import git
    except ImportError as e:
        logger.error(f"Required package not found: {e}")
        logger.error("Please install all required packages: pip install -r requirements.txt")
        sys.exit(1)
        
def load_config(config_path: str) -> Dict[str, Any]:
    """Load configuration from a YAML or JSON file."""
    try:
        with open(config_path, 'r') as f:
            if config_path.endswith(('.yaml', '.yml')):
                return yaml.safe_load(f)
            elif config_path.endswith('.json'):
                return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load config file {config_path}: {e}")
    return {}

def is_programming_file(file_path: Path, include_ext: List[str], exclude_ext: List[str]) -> bool:
    """Determine if a file is a programming file based on its extension."""
    ext = file_path.suffix.lower()
    return ext in include_ext and ext not in exclude_ext

def remove_comments(code: str, file_type: str) -> str:
    """Remove comments based on file type."""
    if file_type in {'.js', '.jsx', '.ts', '.tsx'}:
        # Remove JavaScript/TypeScript comments
        code = re.sub(r'//.*?$', '', code, flags=re.MULTILINE)
        code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
    elif file_type == '.py':
        # Remove Python comments
        code = re.sub(r'#.*?$', '', code, flags=re.MULTILINE)
    elif file_type in {'.html', '.css'}:
        # Remove HTML/CSS comments
        code = re.sub(r'<!--.*?-->', '', code, flags=re.DOTALL)
    return code

def minify_code(code: str, file_type: str) -> str:
    """Minify code using language-specific minifiers when available."""
    try:
        if file_type in {'.js', '.jsx', '.ts', '.tsx'}:
            # For JSX files, we'll use a simple whitespace removal
            return re.sub(r'\s+', ' ', code).strip()
        elif file_type == '.css':
            try:
                import cssmin
                return cssmin.cssmin(code)
            except ImportError:
                logger.warning("cssmin not installed. Falling back to basic CSS minification.")
                return re.sub(r'\s+', ' ', code).strip()
        elif file_type == '.html':
            try:
                import htmlmin
                return htmlmin.minify(code, remove_empty_space=True, remove_comments=True)
            except ImportError:
                logger.warning("htmlmin not installed. Falling back to basic HTML minification.")
                return re.sub(r'>\s+<', '><', re.sub(r'\s+', ' ', code)).strip()
        elif file_type == '.py':
            # Basic Python minification
            lines = code.split('\n')
            minified_lines = [line.strip() for line in lines if line.strip() and not line.strip().startswith('#')]
            return ';'.join(minified_lines)
        else:
            # Generic minification for other file types
            return re.sub(r'\s+', ' ', code).strip()
    except Exception as e:
        logger.error(f"Minification failed for {file_type}: {e}")
        return code  # Return original code if minification fails

def format_code(code: str, file_type: str) -> str:
    """Format code using appropriate formatter based on file type."""
    try:
        if file_type == '.py':
            # Format Python code using Black
            formatted_code = subprocess.run(['black', '-', '--quiet'], input=code.encode('utf-8'), stdout=subprocess.PIPE).stdout.decode('utf-8')
            return formatted_code
        elif file_type in {'.js', '.jsx', '.ts', '.tsx', '.css', '.html'}:
            # Format JavaScript, TypeScript, CSS, HTML using Prettier
            process = subprocess.Popen(['prettier', '--stdin-filepath', f'test{file_type}'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            formatted_code, error = process.communicate(input=code.encode('utf-8'))
            if process.returncode == 0:
                return formatted_code.decode('utf-8')
            else:
                logger.error(f"Prettier formatting failed: {error.decode('utf-8')}")
    except Exception as e:
        logger.error(f"Formatting failed for {file_type}: {e}")
    return code

def generate_tree(root_path: Path, exclude_dirs: set, prefix: str = '', is_last: bool = True) -> str:
    """Recursively generate a tree structure string for the given root_path."""
    tree_str = ''
    try:
        contents = sorted(
            [p for p in root_path.iterdir() if (p.is_dir() and p.name not in exclude_dirs) or p.is_file()],
            key=lambda p: (not p.is_dir(), p.name.lower())
        )

        pointers = ['├── ', '└── ']
        for index, path in enumerate(contents):
            connector = pointers[1] if index == len(contents) - 1 else pointers[0]
            if path.is_dir():
                tree_str += f"{prefix}{connector}{path.name}/\n"
                extension = '    ' if index == len(contents) - 1 else '│   '
                tree_str += generate_tree(path, exclude_dirs, prefix + extension, index == len(contents) - 1)
            else:
                tree_str += f"{prefix}{connector}{path.name}\n"
    except Exception as e:
        logger.error(f"Error generating tree for {root_path}: {e}")
    return tree_str

def clone_github_repo(repo_url: str, branch: str = 'main') -> Optional[Path]:
    """Clone a GitHub repository to a temporary directory."""
    try:
        temp_dir = Path('./temp_repo')
        if temp_dir.exists():
            # Remove existing temp_repo
            for child in temp_dir.glob('*'):
                if child.is_file():
                    child.unlink()
                else:
                    for sub in child.glob('*'):
                        if sub.is_file():
                            sub.unlink()
                    child.rmdir()
            temp_dir.rmdir()
        logger.info(f"Cloning repository {repo_url} (branch: {branch})...")
        Repo.clone_from(repo_url, temp_dir, branch=branch)
        logger.info(f"Repository cloned to {temp_dir.resolve()}")
        return temp_dir
    except Exception as e:
        logger.error(f"Failed to clone repository {repo_url}: {e}")
        return None

async def read_file_async(file_path: Path) -> str:
    """Asynchronously read a file's content."""
    loop = asyncio.get_event_loop()
    try:
        content = await loop.run_in_executor(None, file_path.read_text, 'utf-8')
        return content
    except Exception as e:
        logger.error(f"Error reading file {file_path}: {e}")
        return ''

def extract_metrics(code: str, file_type: str) -> Dict[str, Any]:
    """Extract code metrics based on file type."""
    metrics = {}
    try:
        if file_type == '.py':
            # Using Radon for Python
            raw_metrics = radon_raw_analyze(code)
            metrics['loc'] = raw_metrics.loc
            metrics['lloc'] = raw_metrics.lloc
            metrics['sloc'] = raw_metrics.sloc
            metrics['comments'] = raw_metrics.comments
            metrics['multi'] = raw_metrics.multi
            metrics['blank'] = raw_metrics.blank

            complexity = cc_visit(code)
            total_complexity = sum(block.complexity for block in complexity)
            metrics['cyclomatic_complexity'] = total_complexity

            maintainability = mi_visit(code, False)
            metrics['maintainability_index'] = maintainability
        elif file_type in {'.js', '.jsx', '.ts', '.tsx'}:
            # Basic JavaScript metrics
            lines = code.split('\n')
            metrics['loc'] = len(lines)
            metrics['sloc'] = len([line for line in lines if line.strip()])
            metrics['blank'] = metrics['loc'] - metrics['sloc']
        # Add more language-specific metrics as needed
    except Exception as e:
        logger.error(f"Failed to extract metrics: {e}")
    return metrics

def detect_secrets(code: str, file_type: str, custom_patterns: List[str] = []) -> List[str]:
    """Detect potential secrets in code using regex patterns."""
    secrets = []
    all_patterns = SECRET_PATTERNS + custom_patterns
    
    for pattern in all_patterns:
        matches = re.findall(pattern, code)
        for match in matches:
            # Redact the actual secret value in the output
            redacted = re.sub(r'\S', '*', match)
            secrets.append(f"Potential secret detected: {redacted}")
    
    # Special handling for .env files
    if file_type == '.env':
        env_secrets = re.findall(ENV_SECRET_VARIABLE_PATTERN, code)
        for var, _ in env_secrets:
            secrets.append(f"Potential secret in .env file: {var}=*****")
    
    return secrets

def redact_secrets(code: str, file_type: str) -> str:
    """Redact secrets in the code by replacing them with 'REDACTED'."""
    # Redact general secrets
    for pattern in SECRET_PATTERNS:
        code = re.sub(pattern, 'REDACTED', code)
    
    # Redact .env secrets
    if file_type == '.env':
        code = ENV_SECRET_VARIABLE_PATTERN.sub(r'\g<var>=REDACTED', code)
    
    return code

def remove_secrets(code: str, file_type: str) -> str:
    """Remove secrets from the code."""
    # Remove general secrets
    for pattern in SECRET_PATTERNS:
        code = re.sub(pattern, '', code)
    
    # Remove .env secrets
    if file_type == '.env':
        code = ENV_SECRET_VARIABLE_PATTERN.sub('', code)
    
    return code

def extract_file_metadata(file_path: Path) -> Dict[str, Any]:
    """Extract metadata from a file."""
    try:
        stat = file_path.stat()
        metadata = {
            'size': stat.st_size,
            'created': datetime.datetime.fromtimestamp(stat.st_ctime).isoformat(),
            'modified': datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
            'permissions': oct(stat.st_mode)[-3:]
        }
        return metadata
    except Exception as e:
        logger.error(f"Failed to extract metadata for {file_path}: {e}")
        return {}

def run_linter(file_path: Path, file_type: str) -> List[str]:
    """Run appropriate linter on the file and return linter messages."""
    messages = []
    try:
        if file_type == '.py':
            # Run Flake8
            result = subprocess.run(['flake8', str(file_path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if result.stdout:
                messages.extend(result.stdout.strip().split('\n'))
        elif file_type in {'.js', '.jsx', '.ts', '.tsx'}:
            # Run ESLint
            result = subprocess.run(['eslint', str(file_path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if result.stdout:
                messages.extend(result.stdout.strip().split('\n'))
        # Add more linters for other languages as needed
    except Exception as e:
        logger.error(f"Failed to run linter on {file_path}: {e}")
    return messages

def check_security_misconfigurations(file_path: Path, content: str) -> List[str]:
    misconfigurations = []
    
    if file_path.name == 'package.json':
        # Check for outdated npm packages
        try:
            data = json.loads(content)
            if 'dependencies' in data:
                for package, version in data['dependencies'].items():
                    if version.startswith('^') or version.startswith('~'):
                        misconfigurations.append(f"Potential security risk: {package} version is not pinned")
        except json.JSONDecodeError:
            misconfigurations.append("Invalid package.json file")
    
    elif file_path.suffix == '.py':
        # Check for use of unsafe functions
        unsafe_functions = ['eval', 'exec', 'os.system', 'subprocess.call']
        for func in unsafe_functions:
            if func in content:
                misconfigurations.append(f"Potential security risk: Use of {func} detected")
    
    elif file_path.suffix in {'.js', '.jsx'}:
        # Check for use of 'eval' in JavaScript
        if 'eval(' in content:
            misconfigurations.append("Potential security risk: Use of eval() detected in JavaScript")
    
    # Add more checks for other file types and common misconfigurations
    
    return misconfigurations

async def collect_code_async(root_path: Path, config: Dict[str, Any]) -> Dict[str, Any]:
    """Asynchronously collect code from files based on configuration."""
    collected_data = {
        'tree': generate_tree(root_path, config.get('exclude_dirs', DEFAULT_EXCLUDE_DIRS)),
        'files': []
    }

    # Gather all relevant file paths
    file_paths = [
        p for p in root_path.rglob('*')
        if p.is_file() and is_programming_file(
            p,
            config.get('include_extensions', PROGRAMMING_EXTENSIONS),
            config.get('exclude_extensions', [])
        )
        and not any(excl in p.parts for excl in config.get('exclude_dirs', DEFAULT_EXCLUDE_DIRS))
        and (not config.get('include_dirs') or any(dir in p.parts for dir in config.get('include_dirs')))
    ]

    # Retrieve custom patterns
    custom_patterns = config.get('custom_secret_patterns', [])

    # Initialize progress bar
    for file_path in tqdm(file_paths, desc="Processing files", unit="file"):
        relative_path = file_path.relative_to(root_path)
        code = await read_file_async(file_path)
        file_type = file_path.suffix.lower()

        if code is None:
            logger.warning(f"Failed to read file: {file_path}")
            continue

        # Remove comments if flag is set
        if config.get('remove_comments', False):
            code = remove_comments(code, file_type)

        # Minify code if flag is set
        if config.get('minify', False):
            code = minify_code(code, file_type)

        # Format code if flag is set
        if config.get('format_code', False):
            code = format_code(code, file_type)

        # Extract metrics if flag is set
        metrics = {}
        if config.get('extract_metrics', False):
            metrics = extract_metrics(code, file_type)

        # Detect secrets if flag is set
        secrets = []
        if config.get('detect_secrets', False):
            secrets = detect_secrets(code, file_type, custom_patterns)

        # Handle secrets based on user preference
        if config.get('handle_secrets') == 'redact':
            code = redact_secrets(code, file_type)
        elif config.get('handle_secrets') == 'remove':
            code = remove_secrets(code, file_type)
        # If 'keep', do nothing

        # Run linter if flag is set
        linter_messages = []
        if config.get('run_linter', False):
            linter_messages = run_linter(file_path, file_type)

        # Check for security misconfigurations
        misconfigurations = check_security_misconfigurations(file_path, code)

        # Extract file metadata
        metadata = extract_file_metadata(file_path)

        # Remove blank lines
        code = "\n".join(line for line in code.splitlines() if line.strip())

        collected_data['files'].append({
            'relative_path': str(relative_path),
            'language': file_path.suffix.lstrip('.'),
            'content': code,
            'metadata': metadata,
            'metrics': metrics,
            'secrets': secrets,
            'linter_messages': linter_messages,
            'security_misconfigurations': misconfigurations
        })

    return collected_data

def export_output(collected_data: Dict[str, Any], output_file: str, output_format: str):
    """Export collected data to the specified format."""
    try:
        if output_format == 'markdown':
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("# Code Collection Report\n\n")
                f.write("## Directory Structure:\n")
                f.write("```\n")
                f.write(collected_data['tree'])
                f.write("\n```\n\n")
                for file in collected_data['files']:
                    f.write(f"### File: `{file['relative_path']}`\n\n")
                    f.write(f"**Language:** {file['language']}\n\n")
                    f.write(f"**File Size:** {file['metadata']['size']} bytes\n")
                    f.write(f"**Created:** {file['metadata']['created']}\n")
                    f.write(f"**Modified:** {file['metadata']['modified']}\n\n")
                    if file['metrics']:
                        f.write("**Metrics:**\n\n")
                        for key, value in file['metrics'].items():
                            f.write(f"- {key.replace('_', ' ').title()}: {value}\n")
                        f.write("\n")
                    if file['secrets']:
                        f.write("**Potential Secrets Detected:**\n\n")
                        for secret in file['secrets']:
                            f.write(f"- `{secret}`\n")
                        f.write("\n")
                    if file['linter_messages']:
                        f.write("**Linting Issues:**\n\n")
                        for message in file['linter_messages']:
                            f.write(f"- {message}\n")
                        f.write("\n")
                    if file['security_misconfigurations']:
                        f.write("**Security Misconfigurations:**\n\n")
                        for misconfig in file['security_misconfigurations']:
                            f.write(f"- {misconfig}\n")
                        f.write("\n")
                    f.write(f"```{file['language']}\n")
                    f.write(f"{file['content']}\n")
                    f.write("```\n\n")
        elif output_format == 'json':
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(collected_data, f, indent=4)
        else:  # plain text
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("## Directory Structure:\n")
                f.write(collected_data['tree'])
                f.write("\n\n")
                for file in collected_data['files']:
                    f.write(f"### File: {file['relative_path']}\n")
                    f.write(f"Language: {file['language']}\n")
                    f.write(f"File Size: {file['metadata']['size']} bytes\n")
                    f.write(f"Created: {file['metadata']['created']}\n")
                    f.write(f"Modified: {file['metadata']['modified']}\n")
                    if file['metrics']:
                        f.write("Metrics:\n")
                        for key, value in file['metrics'].items():
                            f.write(f"  - {key.replace('_', ' ').title()}: {value}\n")
                    if file['secrets']:
                        f.write("Potential Secrets Detected:\n")
                        for secret in file['secrets']:
                            f.write(f"  - {secret}\n")
                    if file['linter_messages']:
                        f.write("Linting Issues:\n")
                        for message in file['linter_messages']:
                            f.write(f"  - {message}\n")
                    if file['security_misconfigurations']:
                        f.write("Security Misconfigurations:\n")
                        for misconfig in file['security_misconfigurations']:
                            f.write(f"  - {misconfig}\n")
                    f.write("\n")
                    f.write(f"{file['content']}\n\n")
        logger.info(f"Output successfully written to {output_file} in {output_format} format.")
    except Exception as e:
        logger.error(f"Failed to export output: {e}")

def export_to_pdf(output_file: str, markdown_file: str):
    """Export Markdown file to PDF using Pandoc."""
    try:
        subprocess.run(['pandoc', markdown_file, '-o', output_file], check=True)
        logger.info(f"PDF successfully created at {output_file}")
    except Exception as e:
        logger.error(f"Failed to export PDF: {e}")

def main():
    """Main function to parse arguments, load configurations, and initiate code collection."""
    parser = argparse.ArgumentParser(description="Comprehensive Code Collector CLI Tool")
    parser.add_argument('directory', help='Path of the folder to traverse')
    parser.add_argument('-o', '--output', default='collected_code', help='Output file name without extension')
    parser.add_argument('--config', help='Path to configuration file (YAML or JSON)')
    parser.add_argument('--include-extensions', help='Comma-separated list of extensions to include (overrides config)')
    parser.add_argument('--exclude-extensions', help='Comma-separated list of extensions to exclude (overrides config)')
    parser.add_argument('--include-dirs', help='Comma-separated list of directories to include (overrides config)')
    parser.add_argument('--exclude-dirs', help='Comma-separated list of directories to exclude (overrides config)')
    parser.add_argument('--remove-comments', action='store_true', help='Remove comments from the code (overrides config)')
    parser.add_argument('--minify', action='store_true', help='Minify the code (overrides config)')
    parser.add_argument('--format-code', action='store_true', help='Format code using formatters (overrides config)')
    parser.add_argument('--github', help='GitHub repository URL to clone and process')
    parser.add_argument('--branch', default='main', help='Branch to clone from GitHub repo (default: main)')
    parser.add_argument('--output-format', choices=OUTPUT_FORMATS, default='markdown', help='Output format')
    parser.add_argument('--export-pdf', action='store_true', help='Export Markdown output to PDF')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    parser.add_argument('--extract-metrics', action='store_true', help='Extract code metrics (LOC, cyclomatic complexity)')
    parser.add_argument('--detect-secrets', action='store_true', help='Detect potential secrets in code')
    parser.add_argument('--handle-secrets', choices=['keep', 'redact', 'remove'], default='keep', help='Handle detected secrets: keep, redact, or remove')
    parser.add_argument('--run-linter', action='store_true', help='Run linters on code files')
    parser.add_argument('--custom-secret-patterns', help='Path to a file containing custom regex patterns for secret detection (one per line)')

    args = parser.parse_args()

    # Check for required packages
    check_required_packages()

    # Set logging level
    if args.verbose:
        logger.setLevel(logging.DEBUG)

    # Load configuration
    config = {}
    if args.config:
        config = load_config(args.config)
        logger.debug(f"Configuration loaded from {args.config}: {config}")

    # Override config with command-line arguments if provided
    if args.include_extensions:
        config['include_extensions'] = [ext.strip() for ext in args.include_extensions.split(',')]
    if args.exclude_extensions:
        config['exclude_extensions'] = [ext.strip() for ext in args.exclude_extensions.split(',')]
    if args.include_dirs:
        config['include_dirs'] = [d.strip() for d in args.include_dirs.split(',')]
    if args.exclude_dirs:
        config['exclude_dirs'] = set([d.strip() for d in args.exclude_dirs.split(',')])
    if args.remove_comments:
        config['remove_comments'] = True
    if args.minify:
        config['minify'] = True
    if args.format_code:
        config['format_code'] = True
    if args.extract_metrics:
        config['extract_metrics'] = True
    if args.detect_secrets:
        config['detect_secrets'] = True
    if args.handle_secrets:
        config['handle_secrets'] = args.handle_secrets
    if args.run_linter:
        config['run_linter'] = True

    # Load custom secret patterns from file if provided
    if args.custom_secret_patterns:
        try:
            with open(args.custom_secret_patterns, 'r') as f:
                custom_patterns = [line.strip() for line in f if line.strip()]
            config['custom_secret_patterns'] = custom_patterns
            logger.debug(f"Loaded custom secret patterns from {args.custom_secret_patterns}")
        except Exception as e:
            logger.error(f"Failed to load custom secret patterns from {args.custom_secret_patterns}: {e}")

    # Handle GitHub repository cloning
    if args.github:
        repo_path = clone_github_repo(args.github, args.branch)
        if repo_path:
            root_dir = repo_path
        else:
            logger.error("Exiting due to repository cloning failure.")
            return
    else:
        root_dir = Path(args.directory)

    # Validate directory
    if not root_dir.is_dir():
        logger.error(f"The directory {root_dir} does not exist.")
        return

    # Prevent output path from being inside the input directory
    output_path = Path(args.output).resolve()
    input_path = root_dir.resolve()
    if output_path in input_path.parents or output_path == input_path:
        logger.error("Output path cannot be inside the input directory.")
        return

    # Collect code
    collected_data = asyncio.run(collect_code_async(root_dir, config))

    # Prepare output file path
    output_file = args.output
    if args.output_format == 'markdown':
        output_file += '.md'
    elif args.output_format == 'json':
        output_file += '.json'
    else:
        output_file += '.txt'

    # Ensure output directory exists
    output_dir = Path(output_file).parent
    output_dir.mkdir(parents=True, exist_ok=True)

    # Export collected data
    export_output(collected_data, output_file, args.output_format)

    # Export to PDF if requested
    if args.export_pdf and args.output_format == 'markdown':
        pdf_output = args.output + '.pdf'
        export_to_pdf(pdf_output, output_file)

    # Cleanup cloned repository
    if args.github:
        try:
            logger.info("Cleaning up cloned repository...")
            temp_dir = Path('./temp_repo')
            if temp_dir.exists():
                for child in temp_dir.glob('*'):
                    if child.is_file():
                        child.unlink()
                    else:
                        for sub in child.glob('*'):
                            if sub.is_file():
                                sub.unlink()
                        child.rmdir()
                temp_dir.rmdir()
            logger.info("Cleanup completed.")
        except Exception as e:
            logger.error(f"Failed to cleanup cloned repository: {e}")

if __name__ == '__main__':
    main()