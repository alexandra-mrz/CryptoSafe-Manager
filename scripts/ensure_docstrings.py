#!/usr/bin/env python3
"""Sprint 8 / DOC-4: добавить однострочные docstring публичным символам без документации."""

from __future__ import annotations

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET_DIRS = (
    ROOT / "src" / "core",
    ROOT / "src" / "database",
    ROOT / "src" / "gui",
    ROOT / "src" / "bootstrap.py",
)


def _human(name: str) -> str:
    return name.replace("_", " ").strip()


def _doc_for(node: ast.AST) -> str:
    if isinstance(node, ast.ClassDef):
        return f'"""Публичный класс {_human(node.name)}."""'
    if isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
        if node.name == "main":
            return '"""Точка входа приложения."""'
        return f'"""{_human(node.name).capitalize()}."""'
    return '"""Public API."""'


def _patch_file(path: Path) -> int:
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    lines = source.splitlines(keepends=True)
    inserts: list[tuple[int, str]] = []

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if node.name.startswith("_"):
            continue
        if ast.get_docstring(node, clean=False):
            continue
        body = getattr(node, "body", None)
        if not body:
            continue
        first = body[0]
        indent = " " * (getattr(first, "col_offset", 0) or 0)
        if not indent and hasattr(node, "body") and node.body:
            # fallback indent from first line of node
            line = lines[node.lineno - 1]
            indent = line[: len(line) - len(line.lstrip())] + "    "
        doc_line = f"{indent}{_doc_for(node)}\n"
        inserts.append((first.lineno - 1, doc_line))

    if not inserts:
        return 0

    for lineno, text in sorted(inserts, key=lambda x: -x[0]):
        lines.insert(lineno, text)

    path.write_text("".join(lines), encoding="utf-8")
    return len(inserts)


def main() -> int:
    changed = 0
    files: list[Path] = []
    for item in TARGET_DIRS:
        if item.is_file():
            files.append(item)
        else:
            files.extend(sorted(item.rglob("*.py")))
    for path in files:
        if path.name == "__init__.py":
            continue
        n = _patch_file(path)
        if n:
            print(f"{path.relative_to(ROOT)}: +{n}")
            changed += n
    print(f"Total docstrings added: {changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
