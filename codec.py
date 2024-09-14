import os
from pathlib import Path

# List of programming file extensions
programming_extensions = [
    '.py', '.ipynb', '.js', '.jsx', '.ts', '.tsx', '.html', '.css', '.java', '.c', '.cpp', '.h',
    '.cs', '.rb', '.php', '.go', '.rs', '.swift', '.kt', '.scala', '.pl', '.lua', '.r', '.sql',
    '.sh', '.bat', '.m', '.vb', '.erl', '.ex', '.clj', '.hs', '.s', '.asm', '.ps1', '.groovy',
    '.f', '.f90', '.lisp', '.lsp', '.fs', '.ml', '.jl'
]

def is_programming_file(file_path):
    return file_path.suffix.lower() in programming_extensions

def collect_code(root_dir, output_file):
    root_path = Path(root_dir)
    with open(output_file, 'w', encoding='utf-8') as out_f:
        for file_path in root_path.rglob('*'):
            if file_path.is_file() and is_programming_file(file_path):
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                        code = f.read()
                    out_f.write(f"start of file - {file_path.name}\n")
                    out_f.write(code)
                    out_f.write("\n\n")
                    out_f.write(f"end of code - {file_path.name}\n")
                    out_f.write("\n\n")
                except Exception as e:
                    print(f"Error reading file {file_path}: {e}")

if __name__ == '__main__':
    directory = input("Enter the path of the folder to traverse: ")
    if not os.path.isdir(directory):
        print(f"The directory '{directory}' does not exist.")
    else:
        output_file = 'collected_code.txt'
        collect_code(directory, output_file)
        print(f"Collected code has been written to '{output_file}'.")
