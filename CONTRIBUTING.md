# Contributing safely

Use synthetic fixtures and loopback/isolated labs. Do not commit actual scan reports,
captures, environment files, personal home paths, private infrastructure inventories
or credentials. Read [SECURITY.md](SECURITY.md); report exposures privately.

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip==26.2.1
python -m pip install -r requirements.txt -r security/requirements.txt
# macOS (official Homebrew packages):
brew install gitleaks actionlint
# Linux x86_64: checksum-pinned upstream binaries in a chosen external directory:
python security/install_tools.py /tmp/scanix-security-tools
export PATH="/tmp/scanix-security-tools:$PATH"
# Use a GitHub-verified noreply address; verify it in account settings first.
# Set user.email with --local only; never invent an address from a username.
git config --local core.hooksPath "$PWD/.githooks"
git fetch origin --tags
python security/check.py tree
python security/check.py staged
python security/check.py range --base origin/main --head HEAD
python security/run.py bandit
python security/run.py dependencies
python security/run.py workflows
python -m unittest discover -s security/tests -v
python -B -m unittest discover -s scanix/tests -v
```

The hooks cover all worktrees sharing this Git configuration; an absolute hooksPath
continues to locate the reviewed tools, while scanning the invoking worktree.
Keep the hook worktree available. CI does not depend on local hook installation.
On Windows set `SCANIX_SECURITY_PYTHON=python` for the hooks if the interpreter
is named `python`; use `python` in the manual commands too. CI security jobs
run on Linux, while the regular regression matrix retains Windows/macOS coverage.

Full history: `python security/check.py history --secrets-only` must pass. The
separate `history --privacy-only` inventory currently reports known exposure;
do not delete evidence or weaken patterns to hide it. All scanner reports are
private by default; public output contains locations/categories, never match values.
For deeper tool triage, capture output in a private external directory and review it
without pasting it into issues/logs. Do not run raw verbose scanners on untrusted
content in shared CI logs.

Review the staged diff and outgoing commits before every push. A finding in a
synthetic fixture still needs a narrowly scoped, justified exception; no directory
allowlists. Meaningful tests must prove failure, redaction and resource/range
coverage. Changes to gate scripts, workflow permissions, exception hashes or tools
need careful human review. Do not merge based solely on a green badge.
