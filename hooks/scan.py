"""PostToolUse hook: scan the file Claude just edited and report findings back to Claude."""
import json
import os
import re
import shutil
import subprocess
import sys

MAX_BYTES = 1_000_000
IGNORE_MARKER = "sekyu: ignore"
SOURCE_EXTS = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".html", ".htm",
               ".php", ".rb", ".go", ".java", ".kt", ".kts", ".cs", ".rs", ".c", ".h", ".cpp", ".cc",
               ".hpp", ".swift", ".sh", ".ps1"}
CONFIG_EXTS = {".yaml", ".yml", ".ini", ".toml", ".properties", ".cfg", ".conf"}
TEMPLATE_EXTS = {".example", ".sample", ".template", ".dist"}
SECRET_KEY_WORDS = ("password", "passwd", "secret", "apikey", "api_key", "token")
# Linear: anchored, one greedy class per field, so no ReDoS on huge lines.
UNQUOTED_ASSIGN = re.compile(r"^\s*(?:export\s+)?([\w.-]+)\s*[:=]\s*([^\s'\"#]+)\s*$")


def _rules(*rules):
    return [(rule_id, re.compile(pattern), message) for rule_id, pattern, message in rules]


# Applied to every file: secrets leak from docs and config as easily as from code.
SECRET_RULES = _rules(
    ("aws-key", r"\bAKIA[0-9A-Z]{16}\b", "AWS access key; load it from env or a secret store"),
    ("private-key", r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "private key in file; never commit keys"),
    ("github-token", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", "GitHub token; load it from env"),
    ("anthropic-key", r"\bsk-ant-[A-Za-z0-9_-]{20,}", "Anthropic API key; load it from env"),
    ("hardcoded-secret", r"(?i)\b(password|passwd|secret|api_?key|token)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
     "hardcoded credential; load it from env or a secret store"),
)

# Applied to source files only, so docs that mention eval( stay quiet.
CODE_RULES = _rules(
    ("eval", r"(?<![\w.])eval\s*\(", "eval runs arbitrary code; parse the data instead (json.loads, ast.literal_eval)"),
    ("exec", r"(?<![\w.])exec\s*\(", "exec runs arbitrary code; call the function directly"),
    ("shell-true", r"shell\s*=\s*True", "shell=True enables command injection; pass an argument list"),
    ("os-system", r"\bos\.system\s*\(", "os.system runs a shell; use subprocess.run([...])"),
    ("pickle", r"\bpickle\.loads?\s*\(", "unpickling untrusted data runs code; use json"),
    ("yaml-load", r"\byaml\.(unsafe_)?load\s*\((?!.*Loader\s*=\s*(yaml\.)?C?SafeLoader)",
     "yaml.load without SafeLoader runs code; use yaml.safe_load"),
    ("inner-html", r"\.innerHTML\s*=", "innerHTML with untrusted data is XSS; use textContent or sanitize"),
    ("dangerously-set-html", r"dangerouslySetInnerHTML", "XSS risk; sanitize with DOMPurify or render as text"),
    ("tls-off", r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false", "TLS verification disabled; allows MITM"),
    ("sql-concat", r"\b(execute|query|raw)\s*\(\s*(f[\"']|[\"'][^\"']*[\"']\s*(\+|%\s*[^,)]|\.format\s*\())",
     "SQL built from strings is injectable; use parameterized queries"),
)


def _is_config(path):
    name = os.path.basename(path).lower()
    ext = os.path.splitext(name)[1]
    return ext not in TEMPLATE_EXTS and (name.startswith(".env") or ext in CONFIG_EXTS)


def _unquoted_secret(line):
    """KEY=value / key: value with a secret-looking key and a literal (not ${VAR}, <placeholder>) value."""
    m = UNQUOTED_ASSIGN.match(line)
    if not m:
        return False
    key, value = m.group(1).lower(), m.group(2)
    return any(w in key for w in SECRET_KEY_WORDS) and len(value) >= 8 and value[0] not in "$<%{"


def builtin_findings(path, text, only=None):
    """Scan text line by line. If `only` is given, report just lines whose stripped text is in it."""
    rules = SECRET_RULES + (CODE_RULES if os.path.splitext(path)[1].lower() in SOURCE_EXTS else [])
    config = _is_config(path)
    findings = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if IGNORE_MARKER in line or (only is not None and line.strip() not in only):
            continue
        for rule_id, pattern, message in rules:
            if pattern.search(line):
                findings.append(f"{path}:{lineno}: [{rule_id}] {message}")
        if config and _unquoted_secret(line):
            findings.append(f"{path}:{lineno}: [hardcoded-secret] hardcoded credential; load it from env or a secret store")
    return findings


# Exit code each scanner uses for "found something"; any other non-zero code is a tool error.
FINDING_EXIT = {"semgrep": 1, "gitleaks": 3, "bandit": 1}


def _run(name, cmd):
    """Run a scanner; return its report if it flagged something, else None."""
    try:
        r = subprocess.run(cmd, capture_output=True, encoding="utf-8", errors="replace", timeout=20)
    except Exception:
        return None  # broken or slow scanner: keep built-in result, never block
    out = (r.stdout + r.stderr).strip()
    if r.returncode != FINDING_EXIT[name] or not out:
        return None
    return "\n".join(out.splitlines()[:40])


def external_findings(path):
    path = os.path.abspath(path)  # absolute path can't start with "-", so it is never parsed as a flag
    commands = [
        ["semgrep", "scan", "--config", "p/default", "--metrics=off", "--quiet", "--error", path],
        ["gitleaks", "dir", path, "--no-banner", "--redact", "-v", "--exit-code", "3"],
    ]
    if path.lower().endswith(".py"):
        commands.append(["bandit", "-q", "-ll", path])
    findings = []
    for name, *args in commands:
        exe = shutil.which(name)  # full path: Windows can't launch .cmd shims by bare name
        report = exe and _run(name, [exe, *args])
        if report:
            findings.append(f"[{name}] {report}")
    return findings


def changed_lines(tool_input):
    """Stripped lines Claude just wrote, or None when the whole file is new (Write) or unknown."""
    if "content" in tool_input:
        return None
    parts = [tool_input.get("new_string", "")] + [e.get("new_string", "") for e in tool_input.get("edits", [])]
    text = "\n".join(parts)
    return {line.strip() for line in text.splitlines() if line.strip()} if text.strip() else None


def main():
    try:
        tool_input = json.load(sys.stdin).get("tool_input", {})
        path = tool_input.get("file_path", "")
        if not path or not os.path.isfile(path) or os.path.getsize(path) > MAX_BYTES:
            return 0  # ponytail: files over 1 MB skipped, chunked scan if minified bundles matter
        with open(path, encoding="utf-8", errors="ignore") as f:
            findings = builtin_findings(path, f.read(), changed_lines(tool_input))
        if not os.environ.get("SEKYU_NO_EXTERNAL"):
            findings += external_findings(path)  # ponytail: external scanners see whole file, filter by line if legacy noise hurts
    except Exception:
        return 0  # fail open: a scanner bug must never block editing
    if not findings:
        return 0
    print(f"sekyu found {len(findings)} issue(s). Fix them, or add '{IGNORE_MARKER}' "
          "with a reason if a false positive:", file=sys.stderr)
    print("\n".join(findings), file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
