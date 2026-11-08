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
import shlex
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional


VERSION = "0.2.0"
DEFAULT_MAX_SIZE_MB = 10
DEFAULT_MAX_SCAN_MB = 5
HOOK_START = "# >>> PushCheck managed section >>>"
HOOK_END = "# <<< PushCheck managed section <<<"

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


def staged_blob_size(root: Path, git_path: str) -> int:
    # The leading colon asks Git to inspect the path in the index (staging area).
    result = git_output(root, ["cat-file", "-s", f":{git_path}"])
    if result.returncode != 0:
        error = result.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(error or "Could not inspect staged file size")
    try:
        return int(result.stdout.strip())
    except ValueError as exc:
        raise RuntimeError(f"Git returned an invalid staged file size for {git_path}") from exc


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
            size = staged_blob_size(root, git_path)
        except RuntimeError as exc:
            stats.unreadable_files += 1
            findings.append(Finding("WARNING", "UNREADABLE_STAGED_FILE", display, str(exc)))
            continue
        findings.extend(inspect_file_metadata(display, filename, size, max_size_bytes))
        if size > max_scan_bytes:
            stats.files_skipped_for_size += 1
            continue
        try:
            content = read_staged_blob(root, git_path)
        except RuntimeError as exc:
            stats.unreadable_files += 1
            findings.append(Finding("WARNING", "UNREADABLE_STAGED_FILE", display, str(exc)))
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



def git_path(root: Path, name: str) -> Path:
    result = git_output(root, ["rev-parse", "--git-path", name])
    if result.returncode != 0:
        error = result.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(error or f"Could not resolve Git path: {name}")
    value = Path(result.stdout.decode("utf-8", errors="surrogateescape").strip())
    return (value if value.is_absolute() else root / value).resolve()


def install_hook(root: Path) -> tuple[bool, str]:
    """Install or update a local pre-push hook without overwriting other hooks."""
    hook_path = git_path(root, "hooks/pre-push")
    git_dir_result = git_output(root, ["rev-parse", "--git-dir"])
    if git_dir_result.returncode != 0:
        error = git_dir_result.stderr.decode("utf-8", errors="replace").strip()
        return False, error or "Could not locate the Git metadata directory"
    git_dir_value = Path(git_dir_result.stdout.decode("utf-8", errors="surrogateescape").strip())
    git_dir = (git_dir_value if git_dir_value.is_absolute() else root / git_dir_value).resolve()
    support_script = git_dir / "pushcheck" / "pushcheck.py"

    existing = ""
    if hook_path.exists():
        try:
            existing = hook_path.read_text(encoding="utf-8")
        except OSError as exc:
            return False, f"Cannot read existing pre-push hook: {exc}"
        if HOOK_START not in existing or HOOK_END not in existing:
            return False, (
                f"An existing pre-push hook was found at {hook_path}. "
                "PushCheck did not overwrite it. Add PushCheck to that hook manually or move it first."
            )

    try:
        support_script.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(Path(__file__).resolve(), support_script)
        python_command = Path(sys.executable).as_posix() if os.name == "nt" else sys.executable
        hook_section = (
            f"{HOOK_START}\n"
            f"exec {shlex.quote(python_command)} {shlex.quote(support_script.as_posix())} "
            '--pre-push --remote-name "$1"\n'
            f"{HOOK_END}"
        )
        if existing:
            before, remainder = existing.split(HOOK_START, 1)
            _, after = remainder.split(HOOK_END, 1)
            content = before.rstrip() + "\n" + hook_section + after
        else:
            content = "#!/bin/sh\n" + hook_section + "\n"
        hook_path.parent.mkdir(parents=True, exist_ok=True)
        hook_path.write_text(content, encoding="utf-8", newline="\n")
        try:
            hook_path.chmod(hook_path.stat().st_mode | 0o111)
        except OSError:
            pass
    except OSError as exc:
        return False, f"Could not install the pre-push hook: {exc}"

    return True, f"PushCheck pre-push hook installed: {hook_path}"


def uninstall_hook(root: Path) -> tuple[bool, str]:
    """Remove PushCheck's hook section and its private script copy."""
    hook_path = git_path(root, "hooks/pre-push")
    git_dir_result = git_output(root, ["rev-parse", "--git-dir"])
    if git_dir_result.returncode != 0:
        return False, "Could not locate the Git metadata directory"
    git_dir_value = Path(git_dir_result.stdout.decode("utf-8", errors="surrogateescape").strip())
    git_dir = (git_dir_value if git_dir_value.is_absolute() else root / git_dir_value).resolve()
    support_dir = git_dir / "pushcheck"

    if not hook_path.exists():
        return True, "No pre-push hook is installed."
    try:
        content = hook_path.read_text(encoding="utf-8")
        if HOOK_START not in content or HOOK_END not in content:
            return False, "The existing pre-push hook is not managed by PushCheck; it was left untouched."
        before, remainder = content.split(HOOK_START, 1)
        _, after = remainder.split(HOOK_END, 1)
        remaining = (before + after).strip()
        if remaining in ("", "#!/bin/sh"):
            hook_path.unlink()
        else:
            hook_path.write_text(remaining + "\n", encoding="utf-8", newline="\n")
        support_script = support_dir / "pushcheck.py"
        if support_script.exists():
            support_script.unlink()
        try:
            support_dir.rmdir()
        except OSError:
            pass
    except OSError as exc:
        return False, f"Could not uninstall the pre-push hook: {exc}"
    return True, "PushCheck pre-push hook removed."


def outgoing_commits(root: Path, local_sha: str, remote_sha: str, remote_name: Optional[str]) -> list[str]:
    """Return commits being introduced by this push, oldest first."""
    if not local_sha or set(local_sha) == {"0"}:
        return []  # branch or tag deletion
    if remote_sha and set(remote_sha) != {"0"}:
        rev_args = ["rev-list", "--reverse", f"{remote_sha}..{local_sha}"]
    else:
        rev_args = ["rev-list", "--reverse", local_sha]
        if remote_name:
            rev_args.extend(["--not", f"--remotes={remote_name}"])
    result = git_output(root, rev_args)
    if result.returncode != 0:
        error = result.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(error or "Could not determine commits being pushed")
    return [line.decode("ascii", errors="replace") for line in result.stdout.splitlines() if line]


def changed_paths_in_commit(root: Path, commit: str) -> list[str]:
    result = git_output(root, [
        "diff-tree", "--root", "--no-commit-id", "--name-only", "--no-renames", "-r", "-z", "-m", commit
    ])
    if result.returncode != 0:
        error = result.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(error or f"Could not inspect commit {commit}")
    # Merge commits can list the same path against multiple parents.
    decoded = [item.decode("utf-8", errors="surrogateescape") for item in result.stdout.split(b"\0") if item]
    return list(dict.fromkeys(decoded))


def commit_blob_size(root: Path, commit: str, git_path_name: str) -> Optional[int]:
    object_spec = f"{commit}:{git_path_name}"
    object_type = git_output(root, ["cat-file", "-t", object_spec])
    if object_type.returncode != 0 or object_type.stdout.strip() != b"blob":
        return None  # deleted file, submodule, symlink tree entry, or non-blob object
    result = git_output(root, ["cat-file", "-s", object_spec])
    if result.returncode != 0:
        return None
    try:
        return int(result.stdout.strip())
    except ValueError:
        return None


def read_commit_blob(root: Path, commit: str, git_path_name: str) -> Optional[bytes]:
    result = git_output(root, ["cat-file", "blob", f"{commit}:{git_path_name}"])
    if result.returncode != 0:
        return None
    return result.stdout


def scan_pre_push(
    root: Path,
    remote_name: Optional[str],
    *,
    max_size_bytes: int,
    max_scan_bytes: int,
) -> int:
    """Scan each changed file in commits being pushed and block on findings."""
    updates: list[tuple[str, str, str, str]] = []
    for raw_line in sys.stdin:
        parts = raw_line.strip().split()
        if not parts:
            continue
        if len(parts) != 4:
            print(f"PushCheck: cannot parse pre-push input line: {raw_line.rstrip()!r}", file=sys.stderr)
            return 2
        local_ref, local_sha, remote_ref, remote_sha = parts
        updates.append((local_ref, local_sha, remote_ref, remote_sha))

    findings: list[Finding] = []
    stats = ScanStats()
    scanned_commits: set[str] = set()
    ref_summaries: list[str] = []

    try:
        for local_ref, local_sha, remote_ref, remote_sha in updates:
            if not local_sha or set(local_sha) == {"0"}:
                continue
            commits = outgoing_commits(root, local_sha, remote_sha, remote_name)
            ref_summaries.append(f"{local_ref} -> {remote_ref}: {len(commits)} outgoing commit(s)")
            for commit in commits:
                if commit in scanned_commits:
                    continue
                scanned_commits.add(commit)
                for git_path_name in changed_paths_in_commit(root, commit):
                    display = git_path_name.replace("\\", "/")
                    size = commit_blob_size(root, commit, git_path_name)
                    if size is None:
                        continue
                    stats.files_seen += 1
                    filename = Path(git_path_name).name
                    findings.extend(inspect_file_metadata(display, filename, size, max_size_bytes))
                    for part_index, part in enumerate(Path(git_path_name).parts):
                        if part.casefold() in GENERATED_DIRS:
                            directory = Path(*Path(git_path_name).parts[:part_index + 1]).as_posix()
                            if not any(item.code == "GENERATED_DIRECTORY" and item.path == directory for item in findings):
                                findings.append(Finding(
                                    "WARNING", "GENERATED_DIRECTORY", directory,
                                    "Generated, cached, or dependency directory is tracked in a commit",
                                ))
                    if size > max_scan_bytes:
                        stats.files_skipped_for_size += 1
                        continue
                    content = read_commit_blob(root, commit, git_path_name)
                    if content is None:
                        stats.unreadable_files += 1
                        findings.append(Finding(
                            "WARNING", "UNREADABLE_COMMIT_FILE", display,
                            "Could not read file content from the outgoing commit",
                        ))
                        continue
                    stats.files_content_scanned += 1
                    findings.extend(inspect_text(content, display))

            ignore_check = git_output(root, ["cat-file", "-e", f"{local_sha}:.gitignore"])
            if ignore_check.returncode != 0:
                findings.append(Finding(
                    "WARNING", "MISSING_GITIGNORE", local_ref,
                    "No .gitignore file exists at the pushed revision",
                ))
    except (RuntimeError, OSError) as exc:
        print(f"PushCheck error: {exc}", file=sys.stderr)
        return 2

    print("PushCheck — automatic pre-push inspection")
    if remote_name:
        print(f"Remote: {remote_name}")
    for summary in ref_summaries:
        print(summary)
    print()
    if not updates:
        print("[INFO] Git supplied no references to inspect.")
    for finding in findings:
        location = finding.path + (f":{finding.line}" if finding.line is not None else "")
        print(f"[{finding.severity}] {finding.code}  {location}")
        print(f"         {finding.detail}")
    print()
    if findings:
        print(f"PushCheck found {len(findings)} warning(s). Push blocked.")
        print("Review the findings, fix the issue, and run git push again.")
        print("To bypass local hooks for this one push, Git supports --no-verify; use it only when you understand the risk.")
        return 1
    print(f"[PASS] No configured issues found in {stats.files_seen} changed file version(s). Push allowed.")
    return 0

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
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--install-hook", action="store_true", help="install automatic inspection before git push")
    actions.add_argument("--uninstall-hook", action="store_true", help="remove the PushCheck pre-push hook")
    parser.add_argument("--pre-push", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--remote-name", help=argparse.SUPPRESS)
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
    if args.pre_push and (args.install_hook or args.uninstall_hook):
        parser.error("--pre-push cannot be combined with hook installation options")
    if args.max_size_mb <= 0 or args.max_scan_mb <= 0:
        parser.error("--max-size-mb and --max-scan-mb must be greater than zero")

    try:
        root = find_repository(Path(args.path).expanduser().resolve())
        if args.install_hook:
            ok, message = install_hook(root)
            print(message)
            return 0 if ok else 2
        if args.uninstall_hook:
            ok, message = uninstall_hook(root)
            print(message)
            return 0 if ok else 2
        max_size_bytes = int(args.max_size_mb * 1024 * 1024)
        max_scan_bytes = int(args.max_scan_mb * 1024 * 1024)
        if args.pre_push:
            return scan_pre_push(
                root,
                args.remote_name,
                max_size_bytes=max_size_bytes,
                max_scan_bytes=max_scan_bytes,
            )
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
