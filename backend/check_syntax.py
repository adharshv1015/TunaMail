import ast
import os
import sys

errors = []
warnings = []
all_files = []

for root, dirs, files in os.walk("src"):
    # skip pycache
    dirs[:] = [d for d in dirs if d != "__pycache__"]
    for fn in files:
        if fn.endswith(".py"):
            all_files.append(os.path.join(root, fn))

for fpath in sorted(all_files):
    try:
        src = open(fpath, encoding="utf-8", errors="replace").read()
        tree = ast.parse(src, filename=fpath)
    except SyntaxError as e:
        errors.append(f"SYNTAX ERROR: {fpath}:{e.lineno}: {e.msg}")
    except Exception as e:
        errors.append(f"PARSE ERROR: {fpath}: {e}")

print(f"Checked {len(all_files)} Python files\n")
if errors:
    print("=== SYNTAX ERRORS ===")
    for e in errors:
        print(e)
else:
    print("No syntax errors found.")
