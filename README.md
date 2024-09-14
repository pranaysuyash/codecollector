# Code Collector

A Python script to traverse a directory, generate a tree structure of programming files, and collect their content into a single text file. The script is useful for aggregating code files for documentation or review purposes.

## Features

- Traverse directories and collect programming files based on predefined extensions.
- Exclude specified directories from traversal.
- Generate a directory tree structure including only relevant files and directories.
- Output collected code content with syntax highlighting.

## Installation

1. Clone this repository:

    ```bash
    git clone https://github.com/pranaysuyash/codecollector.git
    ```

2. Navigate into the project directory:

    ```bash
    cd code-collector
    ```

3. (Optional) Create a virtual environment and activate it:

    ```bash
    python -m venv venv
    source venv/bin/activate   # On Windows use `venv\Scripts\activate`
    ```

4. Install required packages:

    ```bash
    pip install -r requirements.txt
    ```

## Usage

Run the script from the command line with the following arguments:

- `directory`: Path to the folder to traverse.
- `-o` or `--output`: Output file name (default: `collected_code.txt`).
- `--exclude`: List of directories to exclude from traversal (default: `.git`, `node_modules`, `__pycache__`).

### Example

```bash
python collect_code.py /path/to/code -o output.txt --exclude .git node_modules
```

This command will traverse `/path/to/code`, generate a tree structure, and collect code files into `output.txt`, excluding directories named `.git` and `node_modules`.

## Script Details

- **File Extensions**: The script includes files with the following extensions:

    ```text
    .py, .ipynb, .js, .jsx, .ts, .tsx, .html, .css, .java, .c, .cpp, .h, .cs, .rb, .php, .go, .rs, .swift, .kt, .scala, .pl, .lua, .r, .sql, .sh, .bat, .m, .vb, .erl, .ex, .clj, .hs, .s, .asm, .ps1, .groovy, .f, .f90, .lisp, .lsp, .fs, .ml, .jl
    ```

- **Tree Generation**: The script generates a directory tree structure, excluding specified directories and only including programming files.

- **Code Collection**: The script collects code from files and writes it into the output file with syntax highlighting.

## Contributing

Feel free to submit issues or pull requests if you have suggestions or improvements.

## License

This project is licensed under the MIT License. See below for details.

### Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

### The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

### THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

