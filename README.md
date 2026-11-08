# PushCheck

**A lightweight Python CLI that checks a Git repository for common mistakes before code is pushed.**

PushCheck can inspect files on disk manually, or install a Git `pre-push` hook so Git runs it automatically whenever you use `git push`.

## Requirements

- Python 3.9 or newer
- Git installed and available on `PATH`
- No third-party Python packages required

## Automatic checks before every push (recommended)

Install the hook in the repository you want to protect:

```bash
python /path/to/PushCheck/pushcheck.py --install-hook /path/to/your-project
```

For example, when `PushCheck` and a Next.js app are sibling folders:

```text
workspace/
├── PushCheck/
│   └── pushcheck.py
└── my-next-app/
    ├── app/
    ├── package.json
    └── .git/
```

Run the installer from `workspace`:

```bash
python PushCheck/pushcheck.py --install-hook my-next-app
```

After installation, just use Git normally:

```bash
cd my-next-app
git add .
git commit -m "Add my changes"
git push
```

Git automatically runs PushCheck before sending commits to the remote. If it finds a configured warning, the push is stopped so you can review and fix it. If the check passes, the push continues.

The installer copies PushCheck into the repository's Git metadata directory. The original PushCheck folder can be moved afterward. The hook is local to that repository, so install it separately in each project you want to protect.

To remove the hook:

```bash
python /path/to/PushCheck/pushcheck.py --uninstall-hook /path/to/your-project
```

The installer will not overwrite an unrelated existing `pre-push` hook. If one already exists, combine the PushCheck command with that hook manually.

## Manual usage

Run a working-tree scan from inside a Git repository:

```bash
python pushcheck.py
```

Scan another repository:

```bash
python pushcheck.py ../my-project
```

Inspect the exact contents currently staged in Git:

```bash
python pushcheck.py --staged
```

The default manual scan checks files on disk, including ignored and untracked files. This is useful for finding local files such as an ignored `.env`. `--staged` checks only added, copied, modified, and renamed files in Git's index.

## What the automatic pre-push hook checks

The hook inspects changed file versions in commits that are about to be pushed, rather than only looking at the current staging area. It checks for:

- Common credential patterns, including private-key headers, AWS access-key IDs, GitHub tokens, Google API keys, Slack tokens, credential-bearing URLs, and likely password/token assignments.
- Sensitive-looking names such as `.env`, `.npmrc`, private-key files, and credential files. Common example files such as `.env.example` are not flagged by name.
- Files larger than the configured size limit (10 MiB by default).
- Common generated files and directories, such as Python bytecode, `__pycache__`, virtual environments, and `node_modules`.
- A missing `.gitignore` file at the pushed revision.

PushCheck reports the file and line for a possible secret, but **does not print the matched secret value**. It checks each outgoing commit, so a secret committed and then deleted in a later commit is still detected in the history being pushed.

## Options

| Option               | Description                                                              |
| -------------------- | ------------------------------------------------------------------------ |
| `path`               | Repository path (default: current directory)                             |
| `--install-hook`     | Install automatic inspection before `git push`                           |
| `--uninstall-hook`   | Remove the PushCheck pre-push hook                                       |
| `--staged`           | Inspect staged Git contents only (manual mode)                           |
| `--max-size-mb N`    | Warn about files larger than `N` MiB (default: `10`)                     |
| `--max-scan-mb N`    | Skip secret-content scanning above `N` MiB (default: `5`)                |
| `--exclude-dir NAME` | Skip an additional directory name in working-tree mode; repeat as needed |
| `--json`             | Print a JSON report for scripts or CI (manual mode)                      |
| `--version`          | Print the version                                                        |

Examples:

```bash
python pushcheck.py --max-size-mb 25 --exclude-dir data
python pushcheck.py --staged --json
```

## Exit codes

- `0`: no configured checks reported a warning
- `1`: one or more warnings were found (the pre-push hook blocks the push)
- `2`: PushCheck could not run, for example because the path is not a Git repository

## Safety and limitations

- PushCheck does not modify, stage, commit, or push project files. Installing or uninstalling the hook changes only Git's local hook files.
- The hook runs locally. It can be bypassed with `git push --no-verify`; do this only when you understand the risk. Repository owners should also use server-side secret scanning or CI checks where available.
- PushCheck is a lightweight heuristic scanner, not a complete secret scanner. It can produce false positives and can miss secrets whose format it does not recognize.
- Files larger than the content-scan limit are still checked for their names and sizes, but their contents are not scanned for secrets.
- A clean report is not a guarantee that a repository is safe to publish. Review the files you intend to push.

## License

No license has been selected yet. Add a license file before inviting others to reuse or redistribute this project.
