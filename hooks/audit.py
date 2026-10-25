"""Read-only repo audit behind /sekyu-audit: secrets in files and history, exposed emails, sensitive tracked files."""
import json
import re
import os
import subprocess
import tempfile
import sys

import guard
import runtimes
import scan

SEVERITIES = ("HIGH", "MEDIUM", "INFO")
NOREPLY = "@users.noreply.github.com"
KEY_EXTS = (".pem", ".key")


def _git(repo, *args):
    git = scan.find_tool("git")  # never a git.exe planted in the audited repo
    if not git:
        raise RuntimeError("git not found")
    r = subprocess.run([git, *guard.SAFE_GIT_ARGS, *args], cwd=repo, capture_output=True, encoding="utf-8", errors="replace")
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
        if not r.stdout.strip():
            return None, None  # nothing to scan (osv-scanner exits 128 with no output when no lockfiles exist)
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


def _osv_findings(repo):
    """osv-scanner reads every lockfile it knows (npm, pip, Go, Rust, Maven, NuGet, ...) without running code."""
    with tempfile.TemporaryDirectory() as d:
        config = os.path.join(d, "osv-scanner.toml")
        open(config, "w").close()  # empty config: the audited repo's own ignore list must not hide its vulns
        data, note = _tool_json(repo, "osv-scanner", ["scan", "source", "--format", "json", "-r", "--config", config, "."])
    if note:
        return [("INFO", note)]
    findings = []
    for result in (data or {}).get("results", []):
        for p in result.get("packages", []):
            pkg = p["package"]
            score = {i: g.get("max_severity") for g in p.get("groups", []) for i in g.get("ids", [])}
            for v in p.get("vulnerabilities", []):
                try:
                    high = float(score.get(v["id"]) or 0) >= 7.0  # CVSS 7+ = high/critical
                except ValueError:
                    high = False
                findings.append(("HIGH" if high else "MEDIUM",
                                 f"{pkg.get('ecosystem', '?')} {pkg['name']} {pkg.get('version', '?')}: {v['id']}"))
    return findings


def dependency_findings(repo):
    """(severity, text) pairs from osv-scanner, or npm audit / pip-audit when osv-scanner is not installed."""
    if scan.find_tool("osv-scanner"):
        try:
            return _osv_findings(repo)
        except Exception:
            return [("INFO", "dependency check osv-scanner output not understood; skipped")]
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


SEMGREP_PACKS = ("p/default", "p/security-audit", "p/command-injection")  # taint rules: input -> exec/shell/deserialize
SEMGREP_SEVERITY = {"ERROR": "HIGH", "WARNING": "MEDIUM"}
SEMGREP_MAX = 100


def semgrep_findings(repo):
    """Whole-repo semgrep scan with RCE/injection data-flow rules, about 30 languages."""
    exe = scan.find_tool("semgrep")
    if not exe:
        return [("INFO", "code vulnerability scan not run: install semgrep (pip install semgrep)")]
    args = [a for pack in SEMGREP_PACKS for a in ("--config", pack)]
    try:
        r = subprocess.run([exe, "scan", *args, "--json", "--metrics=off", "--disable-nosem", "--quiet", "."],
                           cwd=repo, capture_output=True, encoding="utf-8", errors="replace", timeout=600)
        results = json.loads(r.stdout)["results"]
    except Exception as e:
        return [("INFO", f"code vulnerability scan failed ({type(e).__name__}); skipped")]
    findings = []
    for item in results[:SEMGREP_MAX]:
        path = item["path"]
        path = os.path.relpath(path, repo) if os.path.isabs(path) else path
        message = item["extra"].get("message", "").strip().splitlines()[0] if item["extra"].get("message") else ""
        findings.append((SEMGREP_SEVERITY.get(item["extra"].get("severity"), "INFO"),
                         f"{path.replace(os.sep, '/')}:{item['start']['line']}: [semgrep {item['check_id']}] {message}"))
    if len(results) > SEMGREP_MAX:
        findings.append(("INFO", f"semgrep: {len(results) - SEMGREP_MAX} more findings not shown"))
    return findings


def audit(repo=".", external=None):
    """external: run network/slow checks (semgrep, language updates). Default: on unless SEKYU_NO_EXTERNAL is set."""
    if external is None:
        external = not os.environ.get("SEKYU_NO_EXTERNAL")
    result = {s: [] for s in SEVERITIES}
    try:
        repo = _git(repo, "rev-parse", "--show-toplevel").strip()
    except Exception:
        result["INFO"].append(f"{os.path.abspath(repo)}: not a git repository (or git not installed); nothing audited")
        return result

    risky = guard.risky_git_config(repo, git=_git)
    for entry in risky:
        result["HIGH"].append(f"repo git config {entry}: makes git run a program; a hostile repo uses this to run code. "
                              "Review it before running git here")
    hooks = os.path.join(repo, _git(repo, "rev-parse", "--git-path", "hooks").strip())
    if os.path.isdir(hooks):
        for name in sorted(os.listdir(hooks)):
            if not name.endswith(".sample"):
                result["MEDIUM"].append(f".git/hooks/{name}: runs automatically on git operations; review it")

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
        history = _git(repo, "log", "-p", "--all", "--unified=0", "--no-color", "--no-ext-diff", "--no-textconv", "--format=commit %H")
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

    if risky:  # other tools run their own git here; don't hand a hostile repo more chances to run code
        result["INFO"].append("dependency, semgrep and language checks skipped: this repo's git config runs programs")
        return result
    checks = [dependency_findings]
    if external:
        checks += [semgrep_findings, runtimes.runtime_findings]
    for check in checks:
        for severity, text in check(repo):
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
