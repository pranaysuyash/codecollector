import os
from pathlib import Path
import argparse
import re

# List of programming file extensions
programming_extensions = [
    '.py', '.ipynb', '.js', '.jsx', '.ts', '.tsx', '.html', '.css', '.java', '.c', '.cpp', '.h',
    '.cs', '.rb', '.php', '.go', '.rs', '.swift', '.kt', '.scala', '.pl', '.lua', '.r', '.sql',
    '.sh', '.bat', '.m', '.vb', '.erl', '.ex', '.clj', '.hs', '.s', '.asm', '.ps1', '.groovy',
    '.f', '.f90', '.lisp', '.lsp', '.fs', '.ml', '.jl'
]

# Default excluded directories
DEFAULT_EXCLUDE_DIRS = {'.git', 'node_modules', '__pycache__', 'dist'}

def is_programming_file(file_path):
    return file_path.suffix.lower() in programming_extensions

def remove_js_comments(code):
    """Remove comments from JavaScript or React code."""
    code = re.sub(r'//.*?$', '', code, flags=re.MULTILINE)  # Single-line comments
    code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)  # Multi-line comments
    return code

def remove_python_comments(code):
    """Remove comments from Python code."""
    return re.sub(r'#.*?$', '', code, flags=re.MULTILINE)  # Remove single-line comments

def remove_html_comments(code):
    """Remove comments from HTML code."""
    return re.sub(r'<!--.*?-->', '', code, flags=re.DOTALL)  # Remove HTML comments

def remove_comments(code, file_type):
    """Remove comments based on file type."""
    if file_type in {'.js', '.jsx', '.ts', '.tsx'}:
        return remove_js_comments(code)
    elif file_type == '.py':
        return remove_python_comments(code)
    elif file_type in {'.html', '.css'}:
        return remove_html_comments(code)
    return code

def minify_code(code):
    """Minify code by removing extra whitespace and newlines."""
    code = re.sub(r'\s+', ' ', code)  # Replace multiple spaces/newlines with a single space
    return code.strip()  # Trim leading and trailing whitespace

def generate_tree(root_path, exclude_dirs, prefix='', is_last=True):
    """Recursively generate a tree structure string for the given root_path."""
    tree_str = ''
    contents = [p for p in root_path.iterdir() if p.is_dir() and p.name not in exclude_dirs or is_programming_file(p)]
    contents.sort(key=lambda p: (not p.is_dir(), p.name.lower()))

    pointers = ['├── ', '└── ']
    for index, path in enumerate(contents):
        connector = pointers[1] if index == len(contents) - 1 else pointers[0]
        if path.is_dir():
            tree_str += f"{prefix}{connector}{path.name}/\n"
            extension = '    ' if index == len(contents) - 1 else '│   '
            tree_str += generate_tree(path, exclude_dirs, prefix + extension, index == len(contents) - 1)
        else:
            tree_str += f"{prefix}{connector}{path.name}\n"
    return tree_str

def collect_code(root_dir, output_file, remove_comments_flag, minify_flag):
    root_path = Path(root_dir)
    with open(output_file, 'w', encoding='utf-8') as out_f:
        print("Generating directory tree...")
        tree_str = generate_tree(root_path, DEFAULT_EXCLUDE_DIRS)
        out_f.write("Directory Structure:\n")
        out_f.write("```\n")
        out_f.write(tree_str)
        out_f.write("```\n\n")

        print("Collecting code from files...")
        for file_path in root_path.rglob('*'):
            if any(excl in file_path.parts for excl in DEFAULT_EXCLUDE_DIRS):
                continue
            if file_path.is_file() and is_programming_file(file_path):
                relative_path = file_path.relative_to(root_path)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                        code = f.read()
                    
                    # Process the code based on options
                    if remove_comments_flag:
                        code = remove_comments(code, file_path.suffix)
                    if minify_flag:
                        code = minify_code(code)  # Minify only if specified

                    # Remove blank lines
                    code = "\n".join(line for line in code.splitlines() if line.strip())

                    out_f.write(f"## File: {relative_path}\n\n")
                    out_f.write("```{}\n".format(file_path.suffix.lstrip('.')))
                    out_f.write(code)
                    out_f.write("\n```\n\n")
                except Exception as e:
                    print(f"Error reading file {file_path}: {e}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Collect programming code files into a single text file.")
    parser.add_argument('directory', help='Path of the folder to traverse')
    parser.add_argument('-o', '--output', default='collected_code.txt', help='Output file name')
    parser.add_argument('--remove-comments', action='store_true', help='Remove comments from the code')
    parser.add_argument('--minify', action='store_true', help='Minify the code')
    args = parser.parse_args()

    if not os.path.isdir(args.directory):
        print(f"The directory {args.directory} does not exist.")
    else:
        collect_code(args.directory, args.output, args.remove_comments, args.minify)
