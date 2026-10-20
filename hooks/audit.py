"""Read-only repo audit behind /sekyu-audit: secrets in files and history, exposed emails, sensitive tracked files."""
import os
import subprocess
import sys

import guard
import scan

SEVERITIES = ("HIGH", "MEDIUM", "INFO")
NOREPLY = "@users.noreply.github.com"
KEY_EXTS = (".pem", ".key")


def _git(repo, *args):
    r = subprocess.run(["git", *args], cwd=repo, capture_output=True, encoding="utf-8", errors="replace")
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip())
    return r.stdout


def _sensitive(path):
    name = path.rsplit("/", 1)[-1].lower()
    return guard._is_env_file(name) or name.endswith(KEY_EXTS) or name.startswith("id_rsa")


def audit(repo="."):
    result = {s: [] for s in SEVERITIES}
    try:
        repo = _git(repo, "rev-parse", "--show-toplevel").strip()
    except Exception:
        result["INFO"].append(f"{os.path.abspath(repo)}: not a git repository (or git not installed); nothing audited")
        return result

    for path in filter(None, _git(repo, "ls-files", "-z").split("\0")):
        full = os.path.join(repo, path)
        if _sensitive(path):
            result["HIGH"].append(f"{path}: sensitive file is tracked; remove it with 'git rm --cached' and rotate what it holds")
        if not os.path.isfile(full) or os.path.getsize(full) > scan.MAX_BYTES:
            continue  # ponytail: files over 1 MB skipped, same cap as the edit hook
        with open(full, encoding="utf-8", errors="ignore") as f:
            for finding in scan.builtin_findings(path, f.read()):
                rule = finding[len(path) + 1:].split("[", 1)[1].split("]", 1)[0]
                result["HIGH" if rule in scan.SECRET_IDS else "MEDIUM"].append(finding)

    try:
        history = _git(repo, "log", "-p", "--all", "--unified=0", "--no-color", "--no-ext-diff", "--format=commit %H")
    except Exception:
        history = ""  # no commits yet
    result["HIGH"] += [f"history {f} (rewrite history and rotate the secret)" for f in scan.diff_secret_findings(history)]

    try:
        emails = set(_git(repo, "log", "--all", "--format=%ae%n%ce").split())
    except Exception:
        emails = set()
    for email in sorted(emails):
        if email.lower().endswith(NOREPLY):
            result["INFO"].append(f"commit email {email} (noreply, ok)")
        else:
            result["MEDIUM"].append(f"commit email {email} is exposed in history; use a GitHub noreply address")

    for path in filter(None, _git(repo, "ls-files", "-ci", "--exclude-standard", "-z").split("\0")):
        result["MEDIUM"].append(f"{path}: tracked but matches .gitignore; 'git rm --cached' it if it should not be public")
    return result


def report(result):
    total = sum(len(v) for s, v in result.items() if s != "INFO")
    lines = [f"sekyu audit: {total} issue(s)"]
    for severity in SEVERITIES:
        lines.append(f"\n{severity} ({len(result[severity])})")
        lines += [f"  {item}" for item in result[severity]] or ["  none"]
    return "\n".join(lines)


if __name__ == "__main__":
    print(report(audit(sys.argv[1] if len(sys.argv) > 1 else ".")))
