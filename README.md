# PushCheck

**A read-only command-line check for common mistakes before publishing a Git repository.**

PushCheck looks for likely hard-coded credentials, sensitive-looking filenames, oversized files, generated files and directories, and a missing `.gitignore`.

## Requirements

- Python 3.9 or newer
- Git installed and available on `PATH`
- No third-party Python packages required

## Usage

Run the script from inside a Git repository:

```bash
python pushcheck.py
```

Scan a repository at another path:

```bash
python pushcheck.py ../my-project
```

Inspect the exact file contents currently staged in Git:

```bash
python pushcheck.py --staged
```

The default scan checks files on disk, including ignored and untracked files. This is useful for finding local files such as an ignored `.env`. The staged mode checks only added, copied, modified, and renamed files in the Git index.

## Options

| Option | Description |
|---|---|
| `path` | Repository path (default: current directory) |
| `--staged` | Inspect staged Git contents only |
| `--max-size-mb N` | Warn about files larger than `N` MiB (default: `10`) |
| `--max-scan-mb N` | Skip content scanning for files larger than `N` MiB (default: `5`) |
| `--exclude-dir NAME` | Skip an additional directory name in working-tree mode; repeat as needed |
| `--json` | Print a JSON report for scripts or CI |
| `--version` | Print the version |

For example:

```bash
python pushcheck.py --max-size-mb 25 --exclude-dir data
python pushcheck.py --staged --json
```

## What it checks

- Common credential patterns, including private-key headers, AWS access-key IDs, GitHub tokens, Google API keys, Slack tokens, credential-bearing URLs, and likely password/token assignments.
- Sensitive-looking names such as `.env`, `.npmrc`, private-key files, and credential files. Common example files such as `.env.example` are not flagged by name.
- Files larger than the configured size limit.
- Common generated files and directories, such as Python bytecode, `__pycache__`, virtual environments, and `node_modules`.
- Whether a `.gitignore` file exists at the repository root.

PushCheck reports the file and line for a possible secret, but **does not print the matched secret value**.

## Exit codes

- `0`: no configured checks reported a warning
- `1`: one or more warnings were found
- `2`: PushCheck could not run, for example because the path is not a Git repository

## Safety and limitations

- PushCheck is read-only. It does not delete, modify, stage, commit, or push files.
- It is a lightweight heuristic scanner, not a complete secret scanner. It can produce false positives and can miss secrets whose format it does not recognize.
- In working-tree mode, files larger than the content-scan limit are still checked for their names and sizes, but their contents are not scanned for secrets.
- In staged mode, only the staged snapshot is inspected. Unstaged changes and untracked files are not included.
- A clean report is not a guarantee that a repository is safe to publish. Review the findings and the files you intend to push.

## License

No license has been selected yet. Add a license file before inviting others to reuse or redistribute the project.
