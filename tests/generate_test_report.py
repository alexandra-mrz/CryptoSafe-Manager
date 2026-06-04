from __future__ import annotations

# Sprint 8 / TEST-3: генерация отчёта pytest + coverage в tests/report/

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORT_DIR = ROOT / "tests" / "report"


def _run_pytest() -> tuple[int, str]:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    check = subprocess.run(
        [sys.executable, "-m", "pytest", "--version"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if check.returncode != 0:
        msg = (
            f"{sys.executable}: pytest not installed.\n"
            "Activate .venv and run: pip install -r requirements.txt\n"
            "Then: python tests/generate_test_report.py\n"
        )
        (REPORT_DIR / "pytest_console.txt").write_text(msg + (check.stderr or ""), encoding="utf-8")
        return 1, msg

    cmd = [
        sys.executable,
        "-m",
        "pytest",
        "tests/",
        "-k",
        "not test_perf3_qr_generation_under_100ms and not test_export_import_1000_performance",
        "-o",
        "addopts=",
        "-m",
        "not perf",
        f"--cov=src",
        f"--cov-config={ROOT / '.coveragerc'}",
        f"--cov-report=json:{REPORT_DIR / 'coverage.json'}",
        f"--cov-report=html:{REPORT_DIR / 'coverage_html'}",
        f"--cov-report=term",
        f"--html={REPORT_DIR / 'pytest_report.html'}",
        "--self-contained-html",
        "-ra",
    ]
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace")
    output = (proc.stdout or "") + (proc.stderr or "")
    (REPORT_DIR / "pytest_console.txt").write_text(output, encoding="utf-8")
    return proc.returncode, output


def _parse_pytest_summary(output: str) -> dict[str, int | str]:
    summary: dict[str, int | str] = {"passed": 0, "failed": 0, "skipped": 0, "errors": 0, "line": ""}
    for line in reversed(output.splitlines()):
        if " passed" in line or " failed" in line or " skipped" in line:
            summary["line"] = line.strip()
            parts = line.split()
            for i, part in enumerate(parts):
                if part == "passed," and i > 0:
                    summary["passed"] = int(parts[i - 1])
                elif part == "failed," and i > 0:
                    summary["failed"] = int(parts[i - 1])
                elif part == "skipped," and i > 0:
                    summary["skipped"] = int(parts[i - 1])
                elif part == "error" and i > 0 and parts[i - 1].isdigit():
                    summary["errors"] = int(parts[i - 1])
            break
    return summary


def _load_coverage() -> tuple[float, list[tuple[str, float, int, int]]]:
    cov_path = REPORT_DIR / "coverage.json"
    if not cov_path.is_file():
        return 0.0, []
    data = json.loads(cov_path.read_text(encoding="utf-8"))
    total_pct = float(data.get("totals", {}).get("percent_covered", 0.0))
    rows: list[tuple[str, float, int, int]] = []
    for path, info in sorted(data.get("files", {}).items()):
        rel = path.replace("\\", "/")
        if rel.startswith(str(ROOT).replace("\\", "/")):
            rel = rel[len(str(ROOT).replace("\\", "/")) + 1 :]
        summary = info.get("summary", {})
        rows.append(
            (
                rel,
                float(summary.get("percent_covered", 0.0)),
                int(summary.get("covered_lines", 0)),
                int(summary.get("num_statements", 0)),
            )
        )
    return total_pct, rows


def write_summary_markdown(exit_code: int, pytest_output: str) -> Path:
    summary = _parse_pytest_summary(pytest_output)
    total_pct, modules = _load_coverage()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# CryptoSafe Manager — Test Report (Sprint 8)",
        "",
        f"Generated: {now}",
        "",
        "## Test summary",
        "",
        f"- Exit code: `{exit_code}`",
        f"- Result line: `{summary.get('line', 'n/a')}`",
        f"- Passed: **{summary.get('passed', 0)}**",
        f"- Failed: **{summary.get('failed', 0)}**",
        f"- Skipped: **{summary.get('skipped', 0)}**",
        "",
        "## Coverage",
        "",
        f"- **Total: {total_pct:.1f}%** (target ≥ 80%; `pytest --cov=src` + `.coveragerc`)",
        "- Scope: all `src/` except GUI, entrypoints, stubs, QR/OS adapters (see `.coveragerc`).",
        "- Full run: all functional tests except 2 perf micro-benchmarks.",
        "",
        "| Module | Coverage | Covered / Total |",
        "|--------|----------|-----------------|",
    ]
    for rel, pct, covered, total in modules:
        lines.append(f"| `{rel}` | {pct:.1f}% | {covered}/{total} |")
    lines.extend(
        [
            "",
            "## Artifacts",
            "",
            "- `pytest_report.html` — pytest HTML report",
            "- `coverage_html/index.html` — interactive coverage",
            "- `coverage.json` — machine-readable coverage",
            "- `pytest_console.txt` — full console log",
            "",
        ]
    )
    out = REPORT_DIR / "summary.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    return out


def main() -> int:
    exit_code, output = _run_pytest()
    if "pytest not installed" in output:
        print(output.strip())
        return 1
    summary_path = write_summary_markdown(exit_code, output)
    total_pct, _ = _load_coverage()
    print(f"Report written to {summary_path}")
    if exit_code != 0:
        print("Some tests failed — see tests/report/pytest_console.txt")
        if not output.strip() or "passed" not in output:
            print("Coverage below may be stale (from an earlier run).")
        return exit_code
    print(f"Total coverage: {total_pct:.1f}%")
    # exit 1 if coverage below 80% (TEST-2)
    if total_pct < 80.0:
        print("Coverage below 80% target (TEST-2)")
        return 1
    return 0 if exit_code == 0 else exit_code


if __name__ == "__main__":
    raise SystemExit(main())
