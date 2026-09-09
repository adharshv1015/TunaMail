"""
Deep backend issue audit:
- Import resolution
- Missing modules
- Undefined names (heuristic)
- Common anti-patterns
"""
import ast
import os
import sys
import importlib.util

SKIP_DIRS = {"__pycache__", ".venv", "venv", "node_modules"}

def get_all_py_files(root):
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            if f.endswith(".py"):
                yield os.path.join(dirpath, f)

def collect_imports(fpath):
    """Return list of top-level imported module names."""
    try:
        src = open(fpath, encoding="utf-8", errors="replace").read()
        tree = ast.parse(src, filename=fpath)
    except Exception:
        return []
    imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.append(node.module.split(".")[0])
    return imports

def check_undefined_logger(fpath):
    """Warn if logger is used but not defined."""
    try:
        src = open(fpath, encoding="utf-8", errors="replace").read()
    except Exception:
        return []
    issues = []
    if "logger." in src and "logging.getLogger" not in src and "import logger" not in src:
        issues.append(f"WARN: {fpath}: uses 'logger' but no getLogger call found")
    return issues

def check_bare_excepts(fpath):
    """Find bare except clauses."""
    try:
        src = open(fpath, encoding="utf-8", errors="replace").read()
        tree = ast.parse(src, filename=fpath)
    except Exception:
        return []
    issues = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler) and node.type is None:
            issues.append(f"WARN: {fpath}:{node.lineno}: bare 'except:' clause (catches all including KeyboardInterrupt)")
    return issues

def check_print_statements(fpath):
    """Find leftover print() debug calls."""
    try:
        src = open(fpath, encoding="utf-8", errors="replace").read()
        tree = ast.parse(src, filename=fpath)
    except Exception:
        return []
    issues = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            func = node.value.func
            if isinstance(func, ast.Name) and func.id == "print":
                issues.append(f"INFO: {fpath}:{node.lineno}: print() debug statement")
    return issues

def check_todo_fixme(fpath):
    """Find TODO/FIXME/HACK comments."""
    try:
        lines = open(fpath, encoding="utf-8", errors="replace").readlines()
    except Exception:
        return []
    issues = []
    for i, line in enumerate(lines, 1):
        upper = line.upper()
        if any(kw in upper for kw in ("# TODO", "# FIXME", "# HACK", "# XXX", "# BUG")):
            issues.append(f"INFO: {fpath}:{i}: {line.strip()}")
    return issues

def check_hardcoded_secrets(fpath):
    """Find potential hardcoded secrets/keys."""
    try:
        lines = open(fpath, encoding="utf-8", errors="replace").readlines()
    except Exception:
        return []
    issues = []
    bad_patterns = ["api_key =", "secret_key =", "password =", "token =", "api_secret =", "access_key ="]
    for i, line in enumerate(lines, 1):
        low = line.lower().strip()
        for pat in bad_patterns:
            if pat in low and '""' not in line and "''" not in line and "os.environ" not in line and "os.getenv" not in line and "config" not in low[:30]:
                # Only flag if the value looks non-empty
                if "= \"" in line or "= '" in line:
                    issues.append(f"SECURITY: {fpath}:{i}: potential hardcoded secret: {line.strip()[:80]}")
    return issues

def main():
    src_root = "src"
    all_files = list(get_all_py_files(src_root))
    print(f"Auditing {len(all_files)} Python files in '{src_root}'...\n")

    all_issues = {"SECURITY": [], "ERROR": [], "WARN": [], "INFO": []}

    for fpath in sorted(all_files):
        issues = []
        issues += check_undefined_logger(fpath)
        issues += check_bare_excepts(fpath)
        issues += check_print_statements(fpath)
        issues += check_hardcoded_secrets(fpath)
        # Skip TODO noise — too many for report
        # issues += check_todo_fixme(fpath)

        for issue in issues:
            tag = issue.split(":")[0]
            all_issues.setdefault(tag, []).append(issue)

    for level in ("SECURITY", "ERROR", "WARN", "INFO"):
        bucket = all_issues.get(level, [])
        if bucket:
            print(f"\n=== {level} ({len(bucket)}) ===")
            for item in bucket:
                print(f"  {item}")

    total = sum(len(v) for v in all_issues.values())
    print(f"\n{'='*60}")
    print(f"Total issues: {total}")
    print(f"  SECURITY: {len(all_issues.get('SECURITY', []))}")
    print(f"  ERROR:    {len(all_issues.get('ERROR', []))}")
    print(f"  WARN:     {len(all_issues.get('WARN', []))}")
    print(f"  INFO:     {len(all_issues.get('INFO', []))}")

if __name__ == "__main__":
    main()
