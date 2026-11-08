#!/usr/bin/env python3
"""PushCheck: inspect a Git repository for common mistakes before publishing.

The default mode scans files in the working tree (including ignored files),
which is useful for finding local secrets such as an ignored .env file.
Use --staged to inspect the exact file contents currently in Git's index.

PushCheck is a lightweight safety aid, not a guarantee that a repository is
safe to publish. Review every finding before pushing to a remote.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional


VERSION = "0.1.0"
DEFAULT_MAX_SIZE_MB = 10
DEFAULT_MAX_SCAN_MB = 5

# Directories that are usually generated or contain dependencies. They are
# reported once and pruned so PushCheck does not crawl huge environments.
GENERATED_DIRS = {
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "venv",
    "node_modules",
    ".next",
    ".nuxt",
    "coverage",
    "htmlcov",
    "build",
    "dist",
}

GENERATED_FILES = {
    ".ds_store",
    "thumbs.db",
    "desktop.ini",
}
GENERATED_SUFFIXES = {
    ".pyc",
    ".pyo",
    ".class",
    ".o",
    ".obj",
    ".dll",
    ".so",
    ".dylib",
    ".exe",
}

SAFE_ENV_EXAMPLES = {
    ".env.example",
    ".env.sample",
    ".env.template",
    ".env.dist",
}
SENSITIVE_FILENAMES = {
    ".netrc",
    ".npmrc",
    ".pypirc",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "credentials",
    "credentials.json",
    "service-account.json",
    "aws_credentials",
    "secrets.json",
}
SENSITIVE_SUFFIXES = {".pem", ".p12", ".pfx", ".key"}

# These patterns report the location and type of a possible secret, never the
# matched value. Some patterns are intentionally conservative and may need
# review when they flag documentation or test fixtures.
SECRET_PATTERNS = [
    ("Private-key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    (
        "Credential in URL",
        re.compile(r"\bhttps?://[^\s/:@]+:[^\s/@]+@", re.IGNORECASE),
    ),
    (
        "Possible hard-coded credential",
        re.compile(
            r"\b(?:api[_-]?key|client[_-]?secret|secret[_-]?key|password|passwd|"
            r"access[_-]?token|auth[_-]?token|refresh[_-]?token|private[_-]?key)"
            r"\b\s*[:=]\s*[\"']?([A-Za-z0-9_./+=:-]{8,})",
            re.IGNORECASE,
        ),
    ),
]

PLACEHOLDER_VALUES = (
    "your_",
    "your-",
    "replace",
    "change_me",
    "changeme",
    "example",
    "placeholder",
    "insert_",
    "dummy",
    "redacted",
    "xxxxxxxx",
    "xxxxxx",
    "not-a-real",
    "os.getenv",
    "getenv(",
    "none",
    "null",
)


@dataclass(frozen=True)
class Finding:
    severity: str
    code: str
    path: str
    detail: str
    line: Optional[int] = None


@dataclass
class ScanStats:
    files_seen: int = 0
    files_content_scanned: int = 0
    files_skipped_for_size: int = 0
    unreadable_files: int = 0


def git_output(root: Path, args: list[str]) -> subprocess.CompletedProcess:
    """Run Git without a shell, returning stdout/stderr to the caller."""
    return subprocess.run(
        ["git", *args],
        cwd=str(root),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def find_repository(start: Path) -> Path:
    """Return the Git work-tree root or raise a helpful error."""
    if not start.exists():
        raise ValueError(f"Path does not exist: {start}")
    if start.is_file():
        start = start.parent
    result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        cwd=str(start),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise ValueError(f"Not inside a Git repository: {start}")
    return Path(result.stdout.strip()).resolve()


def relative_name(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def is_sensitive_filename(name: str) -> bool:
    lowered = name.casefold()
    if lowered in SAFE_ENV_EXAMPLES:
        return False
    if lowered == ".env" or (lowered.startswith(".env.") and lowered not in SAFE_ENV_EXAMPLES):
        return True
    return lowered in SENSITIVE_FILENAMES or Path(lowered).suffix in SENSITIVE_SUFFIXES


def is_placeholder(value: str) -> bool:
    candidate = value.strip().strip("\"'`;,)").casefold()
    return not candidate or any(token in candidate for token in PLACEHOLDER_VALUES)


def inspect_text(content: bytes, display_path: str) -> list[Finding]:
    """Inspect UTF-8-ish text and return findings without exposing secret values."""
    if b"\x00" in content[:8192]:
        return []  # likely binary
    text = content.decode("utf-8", errors="replace")
    findings: list[Finding] = []
    seen: set[tuple[int, str]] = set()

    for line_number, line in enumerate(text.splitlines(), start=1):
        for label, pattern in SECRET_PATTERNS:
            match = pattern.search(line)
            if not match:
                continue
            # Only the generic assignment rule has a captured value. Avoid
            # warning on common example placeholders and environment lookups.
            if label == "Possible hard-coded credential":
                value = match.group(1)
                if is_placeholder(value):
                    continue
            key = (line_number, label)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    severity="WARNING",
                    code="POSSIBLE_SECRET",
                    path=display_path,
                    line=line_number,
                    detail=f"{label} detected; the matched value is hidden",
                )
            )
    return findings


def inspect_file_metadata(
    display_path: str,
    filename: str,
    size: int,
    max_size_bytes: int,
) -> list[Finding]:
    findings: list[Finding] = []
    if is_sensitive_filename(filename):
        findings.append(
            Finding(
                "WARNING",
                "SENSITIVE_FILENAME",
                display_path,
                "Sensitive-looking file name; verify this file belongs in the repository",
            )
        )
    if size > max_size_bytes:
        mb = size / (1024 * 1024)
        findings.append(
            Finding(
                "WARNING",
                "LARGE_FILE",
                display_path,
                f"File is {mb:.1f} MiB, above the configured {max_size_bytes / (1024 * 1024):.1f} MiB limit",
            )
        )
    lowered = filename.casefold()
    if lowered in GENERATED_FILES or Path(lowered).suffix in GENERATED_SUFFIXES:
        findings.append(
            Finding(
                "WARNING",
                "GENERATED_FILE",
                display_path,
                "Generated or platform-specific file; consider excluding it with .gitignore",
            )
        )
    return findings


def scan_worktree(
    root: Path,
    *,
    max_size_bytes: int,
    max_scan_bytes: int,
    extra_excluded_dirs: set[str],
) -> tuple[list[Finding], ScanStats]:
    """Scan files on disk, including ignored and untracked files."""
    findings: list[Finding] = []
    stats = ScanStats()
    excluded = GENERATED_DIRS | {name.casefold() for name in extra_excluded_dirs}

    for current, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        kept_dirs: list[str] = []
        for dirname in sorted(dirnames):
            candidate = current_path / dirname
            if dirname.casefold() == ".git":
                continue
            if candidate.is_symlink():
                continue
            if dirname.casefold() in excluded:
                findings.append(
                    Finding(
                        "WARNING",
                        "GENERATED_DIRECTORY",
                        relative_name(root, candidate),
                        "Generated, cached, or dependency directory; consider excluding it with .gitignore",
                    )
                )
                continue
            kept_dirs.append(dirname)
        dirnames[:] = kept_dirs

        for filename in sorted(filenames):
            path = current_path / filename
            if path.is_symlink() or not path.is_file():
                continue
            display = relative_name(root, path)
            stats.files_seen += 1
            try:
                size = path.stat().st_size
            except OSError:
                stats.unreadable_files += 1
                findings.append(Finding("WARNING", "UNREADABLE_FILE", display, "Could not read file metadata"))
                continue

            findings.extend(inspect_file_metadata(display, filename, size, max_size_bytes))
            if size > max_scan_bytes:
                stats.files_skipped_for_size += 1
                continue
            try:
                content = path.read_bytes()
            except OSError:
                stats.unreadable_files += 1
                findings.append(Finding("WARNING", "UNREADABLE_FILE", display, "Could not read file contents"))
                continue
            stats.files_content_scanned += 1
            findings.extend(inspect_text(content, display))

    return findings, stats


def staged_paths(root: Path) -> list[str]:
    result = git_output(root, ["diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"])
    if result.returncode != 0:
        error = result.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(error or "Could not list staged files")
    return [item.decode("utf-8", errors="surrogateescape") for item in result.stdout.split(b"\0") if item]


def read_staged_blob(root: Path, git_path: str) -> bytes:
    # The leading colon asks Git to read the path from the index (staging area).
    result = git_output(root, ["cat-file", "blob", f":{git_path}"])
    if result.returncode != 0:
        error = result.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(error or "Could not read staged file")
    return result.stdout


def scan_staged(
    root: Path,
    *,
    max_size_bytes: int,
    max_scan_bytes: int,
) -> tuple[list[Finding], ScanStats]:
    """Inspect staged Git blobs, not the potentially different working copies."""
    findings: list[Finding] = []
    stats = ScanStats()
    for git_path in staged_paths(root):
        display = git_path.replace("\\", "/")
        filename = Path(git_path).name
        stats.files_seen += 1
        try:
            content = read_staged_blob(root, git_path)
        except RuntimeError as exc:
            stats.unreadable_files += 1
            findings.append(Finding("WARNING", "UNREADABLE_STAGED_FILE", display, str(exc)))
            continue
        size = len(content)
        findings.extend(inspect_file_metadata(display, filename, size, max_size_bytes))
        if size > max_scan_bytes:
            stats.files_skipped_for_size += 1
            continue
        stats.files_content_scanned += 1
        findings.extend(inspect_text(content, display))
    return findings, stats


def human_report(
    root: Path,
    mode: str,
    findings: list[Finding],
    stats: ScanStats,
    *,
    has_gitignore: bool,
    max_scan_bytes: int,
) -> None:
    print(f"PushCheck {VERSION} — Git repository inspection")
    print(f"Repository: {root}")
    print(f"Mode: {mode}")
    print()

    if has_gitignore:
        print("[PASS] .gitignore found")
    else:
        print("[WARN] .gitignore is missing; consider adding one")

    if not findings and stats.files_seen == 0:
        print("[INFO] No files were available to scan in this mode.")

    for finding in findings:
        location = finding.path
        if finding.line is not None:
            location += f":{finding.line}"
        print(f"[{finding.severity}] {finding.code}  {location}")
        print(f"         {finding.detail}")

    print()
    warning_count = len(findings) + (0 if has_gitignore else 1)
    print(
        f"Summary: {warning_count} warning(s); {stats.files_seen} file(s) checked; "
        f"{stats.files_content_scanned} file(s) content-scanned."
    )
    if stats.files_skipped_for_size:
        print(
            f"Note: {stats.files_skipped_for_size} file(s) larger than "
            f"{max_scan_bytes / (1024 * 1024):.1f} MiB were not content-scanned."
        )
    if stats.unreadable_files:
        print(f"Note: {stats.unreadable_files} file(s) could not be read.")
    if warning_count:
        print("Review the findings before pushing. PushCheck does not block Git operations.")
    else:
        print("[PASS] No configured checks found an issue.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pushcheck",
        description="Find common secrets and repository clutter before publishing to GitHub.",
        epilog=(
            "Default mode scans files on disk, including ignored and untracked files. "
            "--staged scans the contents currently in Git's index."
        ),
    )
    parser.add_argument("--version", action="version", version=f"PushCheck {VERSION}")
    parser.add_argument("path", nargs="?", default=".", help="repository path (default: current directory)")
    parser.add_argument("--staged", action="store_true", help="inspect staged Git contents only")
    parser.add_argument(
        "--max-size-mb",
        type=float,
        default=DEFAULT_MAX_SIZE_MB,
        metavar="N",
        help=f"warn about files larger than N MiB (default: {DEFAULT_MAX_SIZE_MB})",
    )
    parser.add_argument(
        "--max-scan-mb",
        type=float,
        default=DEFAULT_MAX_SCAN_MB,
        metavar="N",
        help=f"skip secret-content scanning above N MiB (default: {DEFAULT_MAX_SCAN_MB})",
    )
    parser.add_argument(
        "--exclude-dir",
        action="append",
        default=[],
        metavar="NAME",
        help="also skip a directory name (can be repeated; working-tree mode only)",
    )
    parser.add_argument("--json", action="store_true", help="print machine-readable JSON")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.max_size_mb <= 0 or args.max_scan_mb <= 0:
        parser.error("--max-size-mb and --max-scan-mb must be greater than zero")

    try:
        root = find_repository(Path(args.path).expanduser().resolve())
        max_size_bytes = int(args.max_size_mb * 1024 * 1024)
        max_scan_bytes = int(args.max_scan_mb * 1024 * 1024)
        if args.staged:
            findings, stats = scan_staged(
                root,
                max_size_bytes=max_size_bytes,
                max_scan_bytes=max_scan_bytes,
            )
            mode = "staged Git index (exact staged file contents)"
        else:
            findings, stats = scan_worktree(
                root,
                max_size_bytes=max_size_bytes,
                max_scan_bytes=max_scan_bytes,
                extra_excluded_dirs=set(args.exclude_dir),
            )
            mode = "working tree (includes ignored and untracked files)"
        has_gitignore = (root / ".gitignore").is_file()
    except (ValueError, RuntimeError, OSError) as exc:
        print(f"PushCheck error: {exc}", file=sys.stderr)
        return 2

    warning_count = len(findings) + (0 if has_gitignore else 1)
    if args.json:
        payload = {
            "tool": "PushCheck",
            "version": VERSION,
            "repository": str(root),
            "mode": mode,
            "gitignore_found": has_gitignore,
            "stats": asdict(stats),
            "findings": [asdict(item) for item in findings],
            "warning_count": warning_count,
        }
        print(json.dumps(payload, indent=2))
    else:
        human_report(
            root,
            mode,
            findings,
            stats,
            has_gitignore=has_gitignore,
            max_scan_bytes=max_scan_bytes,
        )

    return 1 if warning_count else 0


if __name__ == "__main__":
    raise SystemExit(main())
