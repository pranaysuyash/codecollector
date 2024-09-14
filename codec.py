import os
from pathlib import Path
import argparse

# List of programming file extensions
programming_extensions = [
    '.py', '.ipynb', '.js', '.jsx', '.ts', '.tsx', '.html', '.css', '.java', '.c', '.cpp', '.h',
    '.cs', '.rb', '.php', '.go', '.rs', '.swift', '.kt', '.scala', '.pl', '.lua', '.r', '.sql',
    '.sh', '.bat', '.m', '.vb', '.erl', '.ex', '.clj', '.hs', '.s', '.asm', '.ps1', '.groovy',
    '.f', '.f90', '.lisp', '.lsp', '.fs', '.ml', '.jl'
]

def is_programming_file(file_path):
    return file_path.suffix.lower() in programming_extensions

def generate_tree(root_path, exclude_dirs, prefix='', is_last=True):
    """
    Recursively generate a tree structure string for the given root_path,
    excluding directories specified in exclude_dirs and only including
    programming files.
    """
    tree_str = ''
    # Filter out excluded directories
    contents = [
        p for p in root_path.iterdir()
        if (p.is_dir() and p.name not in exclude_dirs) or is_programming_file(p)
    ]
    # Further filter directories to include only those that contain programming files or subdirectories
    filtered_contents = []
    for p in contents:
        if p.is_dir():
            # Check if the directory contains any programming files or relevant subdirectories
            has_relevant = False
            for sub_p in p.rglob('*'):
                if sub_p.is_dir() and sub_p.name in exclude_dirs:
                    continue
                if sub_p.is_file() and is_programming_file(sub_p):
                    has_relevant = True
                    break
            if has_relevant:
                filtered_contents.append(p)
        else:
            filtered_contents.append(p)
    
    # Sort: directories first, then files, both alphabetically
    filtered_contents.sort(key=lambda p: (not p.is_dir(), p.name.lower()))
    
    pointers = ['├── ', '└── ']
    for index, path in enumerate(filtered_contents):
        connector = pointers[1] if index == len(filtered_contents) - 1 else pointers[0]
        if path.is_dir():
            tree_str += f"{prefix}{connector}{path.name}/\n"
            extension = '    ' if index == len(filtered_contents) - 1 else '│   '
            tree_str += generate_tree(path, exclude_dirs, prefix + extension, index == len(filtered_contents) - 1)
        else:
            tree_str += f"{prefix}{connector}{path.name}\n"
    return tree_str

def collect_code(root_dir, output_file, exclude_dirs):
    root_path = Path(root_dir)
    with open(output_file, 'w', encoding='utf-8') as out_f:
        # Generate and write the tree structure
        print("Generating directory tree...")
        tree_str = generate_tree(root_path, exclude_dirs)
        out_f.write("Directory Structure:\n")
        out_f.write("```\n")
        out_f.write(tree_str)
        out_f.write("```\n\n")

        # Collect and write code files
        print("Collecting code from files...")
        for file_path in root_path.rglob('*'):
            if any(excl in file_path.parts for excl in exclude_dirs):
                continue
            if file_path.is_file() and is_programming_file(file_path):
                relative_path = file_path.relative_to(root_path)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                        code = f.read()
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
    parser.add_argument('--exclude', nargs='*', default=['.git', 'node_modules', '__pycache__'], help='Directories to exclude')
    args = parser.parse_args()

    if not os.path.isdir(args.directory):
        print(f"The directory '{args.directory}' does not exist.")
    else:
        collect_code(args.directory, args.output, args.exclude)
        print(f"Collected code has been written to '{args.output}'.")
