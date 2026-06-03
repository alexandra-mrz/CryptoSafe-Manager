#!/usr/bin/env python3
"""Sprint 8 / DOC-4: проверка docstring у публичных классов и функций в src/."""

from __future__ import annotations

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"


def find_missing() -> list[str]:
    missing: list[str] = []
    for path in sorted(SRC.rglob("*.py")):
        if path.name == "__init__.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if node.name.startswith("_"):
                continue
            if not ast.get_docstring(node):
                missing.append(f"{path.relative_to(ROOT)}:{node.lineno} {node.name}")
    return missing


def main() -> int:
    missing = find_missing()
    if missing:
        print("Public symbols without docstrings:")
        for line in missing:
            print(f"  {line}")
        return 1
    print("DOC-4 OK: all public classes/functions in src/ have docstrings.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
