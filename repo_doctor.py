"""Offline repository readiness scanner with JSON, Markdown and SARIF output."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "target", "dist", "build", ".venv", "venv", "__pycache__", ".pytest_cache", ".idea"}
MAX_FILE_BYTES = 2_000_000
PLACEHOLDER_WORDS = ("example", "sample", "placeholder", "change-me", "your-", "<", ">", "test-only", "test-secret", "dummy", "fake", "replace")

RULES = (
    ("private-key", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"), "high", "Private key material is committed"),
    ("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{30,})\b"), "high", "GitHub access token pattern found"),
    ("cloud-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "high", "Cloud access key pattern found"),
    ("model-api-key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"), "high", "Model API key pattern found"),
    ("generic-secret", re.compile(r"(?i)\b(api[_-]?key|secret|password|token|private[_-]?key)\b\s*[:=]\s*[\"']([^\"']{16,})[\"']"), "medium", "Credential-like assignment found"),
)


def entropy(value: str) -> float:
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values()) if length else 0.0


def looks_like_placeholder(value: str) -> bool:
    lower = value.lower()
    return any(word in lower for word in PLACEHOLDER_WORDS) or (len(set(value)) < 8 and entropy(value) < 3.0)


def iter_files(root: Path) -> Iterable[Path]:
    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(name for name in dirs if name not in SKIP_DIRS and not (Path(directory) / name).is_symlink())
        for name in sorted(files):
            path = Path(directory) / name
            if path.is_symlink():
                continue
            try:
                if path.is_file() and path.stat().st_size <= MAX_FILE_BYTES:
                    yield path
            except OSError:
                continue


def finding(root: Path, path: Path, rule: str, severity: str, message: str, line: int | None = None) -> dict[str, Any]:
    relative = path.relative_to(root).as_posix()
    location = f"{relative}:{line}" if line else relative
    return {"rule": rule, "severity": severity, "message": message, "path": relative, "line": line, "fingerprint": hashlib.sha256(location.encode()).hexdigest()[:16]}


def scan(root: str | Path) -> dict[str, Any]:
    root = Path(root).resolve()
    if not root.is_dir():
        raise ValueError(f"not a directory: {root}")
    findings: list[dict[str, Any]] = []
    manifests: list[str] = []
    file_count = 0
    for path in iter_files(root):
        relative = path.relative_to(root).as_posix()
        file_count += 1
        lower = path.name.lower()
        if lower in {"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "pyproject.toml", "requirements.txt", "pom.xml", "go.mod", "cargo.toml", "cargo.lock"}:
            manifests.append(relative)
        if (lower.startswith(".env") and lower not in {".env.example", ".env.sample"}) or lower in {"credentials.json", "credentials.yml", "application-local.yml", "application-local.yaml", "application-local.properties"} or path.suffix.lower() in {".pem", ".key", ".p12", ".pfx"}:
            findings.append(finding(root, path, "sensitive-file", "medium", "Sensitive configuration or key file is present"))
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for number, line in enumerate(text.splitlines(), 1):
            for rule, pattern, severity, message in RULES:
                for match in pattern.finditer(line):
                    value = match.group(2) if rule == "generic-secret" else match.group(0)
                    if looks_like_placeholder(value):
                        continue
                    level = "high" if rule == "generic-secret" and entropy(value) >= 3.5 else severity
                    findings.append(finding(root, path, rule, level, message, number))
    gitignore = root / ".gitignore"
    ignore_text = gitignore.read_text(encoding="utf-8", errors="replace") if gitignore.exists() else ""
    hygiene = {
        "gitignore_present": gitignore.exists(),
        "env_ignored": any(line.strip() in {".env", ".env.*", "*.env", "**/.env"} for line in ignore_text.splitlines()),
        "build_dirs_ignored": any(token in ignore_text for token in ("node_modules", "target/", "dist/")),
    }
    manifests = sorted(set(manifests))
    commands = []
    if (root / "package.json").exists():
        try:
            package = json.loads((root / "package.json").read_text(encoding="utf-8"))
            scripts = package.get("scripts", {}) if isinstance(package, dict) else {}
        except (ValueError, OSError):
            scripts = {}
        commands.append("npm ci" if (root / "package-lock.json").exists() else "npm install")
        if "test" in scripts: commands.append("npm test")
        if "build" in scripts: commands.append("npm run build")
    if (root / "pom.xml").exists(): commands.append("mvn -B verify")
    if (root / "pyproject.toml").exists() or (root / "requirements.txt").exists(): commands.append("python -m pytest")
    if list((root / "tests").glob("test_*.py")):
        commands.append("python -m unittest discover -s tests -v")
    counts = Counter(item["severity"] for item in findings)
    return {
        "root": str(root), "files_scanned": file_count, "manifests": manifests,
        "hygiene": hygiene, "suggested_commands": commands, "findings": findings,
        "summary": {"high": counts["high"], "medium": counts["medium"], "low": counts["low"], "total": len(findings)},
    }


def markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [f"# Repository Doctor\n", f"Scanned `{report['root']}`", "", f"- Files scanned: **{report['files_scanned']}**", f"- Findings: **{summary['total']}** (high {summary['high']}, medium {summary['medium']}, low {summary['low']})", f"- Gitignore: **{'ready' if report['hygiene']['gitignore_present'] else 'missing'}**", ""]
    lines.append("## Findings\n")
    if not report["findings"]: lines.append("No configured secret or sensitive-file findings. This is a targeted readiness scan, not a complete security audit.\n")
    else:
        lines.append("| Severity | Rule | Location | Message |\n| --- | --- | --- | --- |")
        lines.extend(f"| {item['severity']} | `{item['rule']}` | `{item['path']}:{item['line'] or ''}` | {item['message']} |" for item in report["findings"])
    lines.extend(["", "## Detected manifests\n", *[f"- `{item}`" for item in report["manifests"]], "", "## Suggested checks\n", *[f"- `{item}`" for item in report["suggested_commands"]]])
    return "\n".join(lines) + "\n"


def sarif(report: dict[str, Any]) -> dict[str, Any]:
    rules = {item["rule"]: {"id": item["rule"], "shortDescription": {"text": item["message"]}} for item in report["findings"]}
    results = [{"ruleId": item["rule"], "level": "error" if item["severity"] == "high" else "warning", "message": {"text": item["message"]}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": item["path"]}, **({"region": {"startLine": item["line"]}} if item["line"] else {})}}]} for item in report["findings"]]
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [{"tool": {"driver": {"name": "repo-doctor", "rules": list(rules.values())}}, "results": results}]}


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan a repository before publishing or deploying it")
    parser.add_argument("path", nargs="?", default=".")
    parser.add_argument("--format", choices=("text", "json", "markdown", "sarif"), default="text")
    parser.add_argument("--output", help="write report to a file")
    parser.add_argument("--fail-on-high", action="store_true")
    args = parser.parse_args()
    try:
        report = scan(args.path)
    except ValueError as error:
        print(error, file=sys.stderr)
        return 2
    if args.format == "json": output = json.dumps(report, ensure_ascii=False, indent=2)
    elif args.format == "markdown": output = markdown(report)
    elif args.format == "sarif": output = json.dumps(sarif(report), ensure_ascii=False, indent=2)
    else:
        output = f"Repository Doctor: {report['root']}\nFiles: {report['files_scanned']}\nFindings: {report['summary']}\n" + "\n".join(f"[{item['severity']}] {item['path']}:{item['line'] or '-'} {item['message']}" for item in report["findings"])
    if args.output: Path(args.output).write_text(output + ("" if output.endswith("\n") else "\n"), encoding="utf-8")
    else: print(output)
    return 1 if args.fail_on_high and report["summary"]["high"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
