import ast
from pathlib import Path
import re
import sys

STDLIB_MODULES = sys.stdlib_module_names if hasattr(sys, "stdlib_module_names") else {
    "os", "sys", "re", "json", "ast", "math", "time", "datetime", "typing",
    "collections", "itertools", "functools", "pathlib", "subprocess", "hashlib",
    "socket", "ssl", "threading", "multiprocessing", "asyncio", "logging"
}

def extract_ast_imports(file_path: Path) -> set[str]:
    try:
        content = file_path.read_text(encoding="utf-8")
        tree = ast.parse(content, filename=str(file_path))
    except Exception:
        return set()

    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top_pkg = alias.name.split(".")[0]
                if top_pkg not in STDLIB_MODULES and not top_pkg.startswith("_"):
                    imported.add(top_pkg)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                top_pkg = node.module.split(".")[0]
                if top_pkg not in STDLIB_MODULES and not top_pkg.startswith("_"):
                    imported.add(top_pkg)
    return imported

def extract_from_requirements(req_path: Path) -> set[str]:
    packages = set()
    if not req_path.is_file():
        return packages

    for line in req_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        pkg = re.split(r"[><=~!;]", line)[0].strip()
        if pkg:
            packages.add(pkg.lower())
    return packages
