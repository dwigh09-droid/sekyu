# sekyu

**A security guard for Claude Code.** sekyu watches what your AI coding assistant writes and runs, catches security mistakes as they happen, and makes Claude fix them before moving on.

## What is sekyu?

AI assistants write code fast, including insecure code: hardcoded passwords, `eval` on user input, SQL built from strings, dangerous shell commands. sekyu is a free, open-source plugin for [Claude Code](https://claude.com/claude-code) that puts real security checks in the loop instead of trusting the model to remember the rules:

- **Checks every edit.** Each file Claude writes is scanned for leaked secrets and risky code (built-in rules, plus semgrep, gitleaks and bandit when installed). Findings go straight back to Claude, which fixes them.
- **Blocks dangerous commands.** `curl ... | sh`, `rm -rf /`, force pushes, committing `.env` files, and commits that would publish your personal email or secrets are stopped before they run.
- **Audits whole repos** with `/sekyu-audit`: secrets in files and git history, exposed commit emails, code vulnerabilities in about 30 languages, vulnerable dependencies in every major ecosystem, outdated or end-of-life language versions, and git configs that run hidden commands.
- **Hunts RCE** with `/sekyu-rce`: an AI agent that traces attacker input to code-execution bugs in any language and proves each one with a harmless test before reporting it.

Prompts are suggestions; hooks always run. sekyu puts deterministic checks in the loop instead of trusting the model to remember secure-coding rules.

> sekyu reduces risk. It does not make code "secure". Pattern matching misses logic flaws, auth bugs, and anything context-dependent. Keep running `/security-review` and real code review before shipping.

## What it does

| Part | Trigger | Behavior |
|---|---|---|
| `hooks/scan.py` | After `Edit`, `Write`, `MultiEdit` | Scans the changed file. Findings: exit code 2, report sent to Claude, Claude fixes. Clean: silent. |
| `hooks/guard.py` | Before `Bash`, `PowerShell` | Blocks dangerous commands (pipe-to-shell, `rm -rf /`, force push, `chmod 777`, committing `.env`). Claude is told why. |
| `hooks/guard.py` | Before `git commit`, `git push` | Blocks if the repo's own `.git/config` makes git run programs, or if `git config user.email` is not a `@users.noreply.github.com` address, so Claude asks you first. On commit, also blocks secrets in the staged diff (or all tracked changes for `commit -a`). |
| `/sekyu-audit` | You run it | Read-only audit of the whole repo and its history, code vulnerabilities, dependencies, and language versions. See [Repo audit](#repo-audit). |
| `/sekyu-rce` | You run it | Deep AI hunt for code execution bugs (RCE) that pattern scanners miss. See [RCE hunt](#rce-hunt). |
| `skills/secure-coding` | Claude loads it when writing code that touches input, auth, SQL, files, or secrets | Short rule set: validate at trust boundaries, parameterized queries, encode output, no hardcoded secrets, least privilege. |

### Scan layers

1. **Built-in rules** (always on, no install needed): hardcoded secrets (AWS keys, private keys, GitHub/Anthropic tokens, `password = "..."`) in any file; risky code (`eval`, `exec`, `shell=True`, `os.system`, `pickle.load`, unsafe `yaml.load`, `innerHTML`, `dangerouslySetInnerHTML`, `verify=False`, string-built SQL) in source files.
2. **External scanners** (used only if found on `PATH`): `semgrep`, `gitleaks`, `bandit` (Python files).

On `Edit`/`MultiEdit`, built-in rules report only the lines Claude just wrote, so legacy code in the same file does not cause a fix loop. External scanners see the whole file.

If an external scanner crashes, errors, or times out (20 s each), sekyu skips it and keeps the built-in result. It never blocks you on a broken tool.

### Commit guard

Before Claude runs `git commit` or `git push`, sekyu checks the identity git will publish. A personal or work email in `user.email` ends up in public commit history, so anything other than a GitHub noreply address is blocked and Claude asks you what to do. Set the noreply address for the repo:

```bash
git config user.email "<id>+<username>@users.noreply.github.com"
```

On `git commit`, the added lines of the staged diff are scanned for secrets with the built-in rules. Any git error or timeout (4 s per call) lets the command through: the guard never blocks on a broken tool.

### Repo audit

`/sekyu-audit` runs `hooks/audit.py` and reports findings grouped by severity. It changes nothing.

| Severity | Finding |
|---|---|
| HIGH | Repo git config entries (`.git/config` and `.git/config.worktree`) that make git run programs (`core.fsmonitor`, textconv, filters, `!` aliases, hooksPath, `ext::` remotes, `gpg.ssh.defaultKeyCommand`, and more; sign of a hostile repo; other checks are then skipped); semgrep ERROR findings (RCE, injection); vulnerable dependencies with CVSS 7+; end-of-life language runtimes; secrets in tracked files; secrets in any commit on any branch (`git log -p --all`, added lines); tracked sensitive files (`.env*` except templates, `*.pem`, `*.key`, `id_rsa*`) |
| MEDIUM | Non-sample scripts in `.git/hooks`; semgrep WARNING findings; other vulnerable dependencies; runtimes missing security patches; risky code in tracked files; commit author/committer emails that are not GitHub noreply; tracked files that `.gitignore` now excludes |
| INFO | Noreply commit emails; dependency checks that did not run |

**Code vulnerabilities.** If `semgrep` is installed, the whole repo is scanned with the `p/default`, `p/security-audit`, and `p/command-injection` rule packs. These follow untrusted input to code execution, shell commands, unsafe deserialization, and injection sinks in about 30 languages. `nosemgrep` comments are ignored during audits, because an audited repo controls them. Rules download from semgrep.dev.

**Dependencies.** If `osv-scanner` is installed, it reads every lockfile it knows (npm, PyPI, Go, Rust, Maven, NuGet, Composer, RubyGems, and more) without running any project code; CVSS 7+ is HIGH. The repo's own `osv-scanner.toml` ignore list is not used. Package names and versions are sent to osv.dev. Without osv-scanner, the audit falls back to `npm audit --json` for JS lockfiles and to `pip-audit --disable-pip --no-deps` for `requirements*.txt` files that contain only exact `name==version` lines. Other requirements files are skipped, because resolving them makes pip build packages, which runs code from the repo.

**Language updates.** For each runtime the project uses (Python, Node.js, Go, Ruby, PHP), the audit takes the version from pin files (`.python-version`, `.nvmrc`, `.node-version`, `go.mod`, `.ruby-version`), from Dockerfile `FROM` images, or from the installed runtime. It checks that version against endoflife.date: end of life is HIGH, a missing patch release is MEDIUM. Only the runtime name is sent.

Set `SEKYU_NO_EXTERNAL=1` to skip the semgrep scan and the language check (no network). Each external tool fails open: when one is missing or errors, you get an INFO note.

A secret found in history stays public after you delete the file: rotate it, then rewrite history if needed. Run it directly with `python hooks/audit.py [repo]`.

### RCE hunt

`/sekyu-rce [path or focus]` starts the `rce-hunter` agent. It maps every input an attacker controls, traces each one to code-execution sinks in any language, and tries to trigger each candidate with a harmless marker in a temporary copy. Sinks include dynamic code, shell and argument injection, deserialization, template injection, dynamic imports, package builds, attacker config files, planted executables, file writes that lead to code, chained web bugs, and memory corruption. Findings are reported as **proven** (the marker ran) or **suspected**. It never runs the repo's own install, build, or test scripts. It uses many tokens on large codebases. A clean result means no RCE was found in what was read, not a guarantee.

### False positives

Add `sekyu: ignore` in a comment on the flagged line:

```python
result = eval(expr)  # sekyu: ignore -- expr is a constant from config.py
```

## Install

Requires Python 3.9+ on `PATH` as `python`.

In Claude Code:

```
/plugin marketplace add dwigh09-droid/sekyu
/plugin install sekyu@sekyu
```

Restart the session. Optional, for deeper scans:

```bash
pip install semgrep bandit pip-audit
```

```bash
winget install gitleaks
```

```bash
winget install Google.OSVScanner
```

## Develop

```bash
python -m unittest discover -s tests -v
```

Set `SEKYU_NO_EXTERNAL=1` to run only built-in rules (tests do this).

CI (`.github/workflows/security.yml`) runs the tests, gitleaks over full history, and semgrep `p/default` on every push and pull request to `main`. Dependabot keeps the actions current.

## Layout

```
.claude-plugin/plugin.json       plugin manifest
.claude-plugin/marketplace.json  local marketplace entry
hooks/hooks.json                 hook wiring
hooks/scan.py                    post-edit file scanner
hooks/guard.py                   pre-command blocker and commit guard
hooks/audit.py                   repo audit behind /sekyu-audit
hooks/runtimes.py                language-update check (endoflife.date)
commands/sekyu-audit.md          /sekyu-audit slash command
commands/sekyu-rce.md            /sekyu-rce slash command
agents/rce-hunter.md             RCE hunting agent
skills/secure-coding/SKILL.md    secure-coding rules for Claude
tests/                           unittest suite
```
