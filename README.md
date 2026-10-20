# sekyu

A Claude Code plugin that checks every file Claude writes and every shell command Claude runs, and pushes findings back to Claude so it fixes them before moving on.

Prompts are suggestions; hooks always run. sekyu puts deterministic checks in the loop instead of trusting the model to remember secure-coding rules.

> sekyu reduces risk. It does not make code "secure". Pattern matching misses logic flaws, auth bugs, and anything context-dependent. Keep running `/security-review` and real code review before shipping.

## What it does

| Part | Trigger | Behavior |
|---|---|---|
| `hooks/scan.py` | After `Edit`, `Write`, `MultiEdit` | Scans the changed file. Findings: exit code 2, report sent to Claude, Claude fixes. Clean: silent. |
| `hooks/guard.py` | Before `Bash`, `PowerShell` | Blocks dangerous commands (pipe-to-shell, `rm -rf /`, force push, `chmod 777`, committing `.env`). Claude is told why. |
| `skills/secure-coding` | Claude loads it when writing code that touches input, auth, SQL, files, or secrets | Short rule set: validate at trust boundaries, parameterized queries, encode output, no hardcoded secrets, least privilege. |

### Scan layers

1. **Built-in rules** (always on, no install needed): hardcoded secrets (AWS keys, private keys, GitHub/Anthropic tokens, `password = "..."`) in any file; risky code (`eval`, `exec`, `shell=True`, `os.system`, `pickle.load`, unsafe `yaml.load`, `innerHTML`, `dangerouslySetInnerHTML`, `verify=False`, string-built SQL) in source files.
2. **External scanners** (used only if found on `PATH`): `semgrep`, `gitleaks`, `bandit` (Python files).

On `Edit`/`MultiEdit`, built-in rules report only the lines Claude just wrote, so legacy code in the same file does not cause a fix loop. External scanners see the whole file.

If an external scanner crashes, errors, or times out (20 s each), sekyu skips it and keeps the built-in result. It never blocks you on a broken tool.

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
pip install semgrep bandit
```

```bash
winget install gitleaks
```

## Develop

```bash
python -m unittest discover -s tests -v
```

Set `SEKYU_NO_EXTERNAL=1` to run only built-in rules (tests do this).

## Layout

```
.claude-plugin/plugin.json       plugin manifest
.claude-plugin/marketplace.json  local marketplace entry
hooks/hooks.json                 hook wiring
hooks/scan.py                    post-edit file scanner
hooks/guard.py                   pre-command blocker
skills/secure-coding/SKILL.md    secure-coding rules for Claude
tests/                           unittest suite
```
