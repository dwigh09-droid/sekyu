"""Read-only repo audit behind /sekyu-audit: secrets in files and history, exposed emails, sensitive tracked files."""
import json
import re
import os
import subprocess
import sys

import guard
import scan

SEVERITIES = ("HIGH", "MEDIUM", "INFO")
NOREPLY = "@users.noreply.github.com"
KEY_EXTS = (".pem", ".key")


def _git(repo, *args):
    git = scan.find_tool("git")  # never a git.exe planted in the audited repo
    if not git:
        raise RuntimeError("git not found")
    r = subprocess.run([git, *args], cwd=repo, capture_output=True, encoding="utf-8", errors="replace")
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip())
    return r.stdout


def _sensitive(path):
    name = path.rsplit("/", 1)[-1].lower()
    return guard._is_env_file(name) or name.endswith(KEY_EXTS) or name.startswith("id_rsa")


NPM_LOCKS = ("package-lock.json", "pnpm-lock.yaml", "yarn.lock")
PY_MANIFESTS = ("pyproject.toml", "poetry.lock")
NPM_HIGH = {"critical", "high"}


def _tool_json(repo, name, args):
    """Run a dependency scanner; JSON output, or an INFO note when missing or broken. Never raises."""
    exe = scan.find_tool(name)  # full path, never from the audited folder
    if not exe:
        return None, f"dependency check not run: install {name}"
    try:
        # Exit code is non-zero when vulnerabilities are found, so parse stdout either way.
        r = subprocess.run([exe, *args], cwd=repo, capture_output=True, encoding="utf-8", errors="replace", timeout=60)
        return json.loads(r.stdout), None
    except Exception as e:
        return None, f"dependency check {name} failed ({type(e).__name__}); skipped"


def _npm_findings(repo):
    data, note = _tool_json(repo, "npm", ["audit", "--json"])
    if note:
        return [("INFO", note)]
    try:
        with open(os.path.join(repo, "package-lock.json"), encoding="utf-8") as f:
            installed = json.load(f).get("packages", {})
    except Exception:
        installed = {}
    findings = []
    for pkg, v in data.get("vulnerabilities", {}).items():
        version = installed.get(f"node_modules/{pkg}", {}).get("version", f"in {v.get('range', '?')}")
        fix = v.get("fixAvailable")
        fixed = fix.get("version", "?") if isinstance(fix, dict) else ("available" if fix else "none")
        severity = v.get("severity", "?")
        findings.append(("HIGH" if severity in NPM_HIGH else "MEDIUM",
                         f"npm {pkg} {version}: {severity} vulnerability, fixed in {fixed}"))
    return findings


# Only exact `name==version` lines (optional extras, env marker, comment). Anything else (options, URLs,
# local paths, ranges) would need pip to resolve or build, which runs code from the audited repo.
PINNED_LINE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(\[[A-Za-z0-9._,\s-]*\])?\s*==\s*[A-Za-z0-9.!+_-]+\s*(;[^#]*)?(#.*)?$")


def _is_pinned_only(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        lines = [line.strip() for line in f]
    return all(not line or line.startswith("#") or PINNED_LINE.match(line) for line in lines)


def _pip_findings(repo, requirements):
    # --disable-pip --no-deps: pip-audit only parses the files, never runs pip (no builds, no index URLs).
    args = ["-f", "json", "--disable-pip", "--no-deps"] + [a for req in requirements for a in ("-r", req)]
    data, note = _tool_json(repo, "pip-audit", args)
    if note:
        return [("INFO", note)]
    deps = data.get("dependencies", []) if isinstance(data, dict) else data  # older pip-audit: bare list
    # pip-audit reports no severity, so every known vulnerability is HIGH.
    return [("HIGH", f"pip {d['name']} {d['version']}: {v['id']}, fixed in {', '.join(v.get('fix_versions') or ['none'])}")
            for d in deps for v in d.get("vulns", [])]


def dependency_findings(repo):
    """(severity, text) pairs from npm audit / pip-audit, for whichever manifests exist at the repo root."""
    names = os.listdir(repo)
    findings = []
    requirements = []
    for n in sorted(n for n in names if n.startswith("requirements") and n.endswith(".txt")):
        if _is_pinned_only(os.path.join(repo, n)):
            requirements.append(n)
        else:
            findings.append(("INFO", f"{n} skipped: only exact name==version lines are audited "
                                     "(options, URLs, paths, ranges or hashes would make pip run repo code)"))
    for n in PY_MANIFESTS:
        if n in names and not requirements:
            findings.append(("INFO", f"{n} not audited: export pinned requirements.txt to check Python deps"))
    checks = []
    if any(n in names for n in NPM_LOCKS):
        checks.append(("npm", lambda: _npm_findings(repo)))
    if requirements:
        checks.append(("pip-audit", lambda: _pip_findings(repo, requirements)))
    for name, check in checks:
        try:
            findings += check()
        except Exception:
            findings.append(("INFO", f"dependency check {name} output not understood; skipped"))
    return findings


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

    for severity, text in dependency_findings(repo):
        result[severity].append(text)
    return result


def report(result):
    total = sum(len(v) for s, v in result.items() if s != "INFO")
    lines = [f"sekyu audit: {total} issue(s)"]
    for severity in SEVERITIES:
        lines.append(f"\n{severity} ({len(result[severity])})")
        lines += [f"  {item}" for item in result[severity]] or ["  none"]
    return "\n".join(lines)


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # non-ASCII paths/emails on cp1252 consoles
    print(report(audit(sys.argv[1] if len(sys.argv) > 1 else ".")))
