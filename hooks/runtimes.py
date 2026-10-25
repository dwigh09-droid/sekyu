"""Language-update check for /sekyu-audit: is each runtime the project uses end of life or missing patches?

Versions come from pin files, Dockerfile base images, or the installed runtime. Support data comes from
endoflife.date (only the product name is sent).
"""
import datetime
import json
import os
import re
import subprocess
import urllib.request

import scan

# Which files mean the project uses a runtime.
USES = {
    "python": (".py", "pyproject.toml", "setup.py", "Pipfile", "requirements.txt"),
    "nodejs": (".js", ".ts", "package.json"),
    "go": (".go", "go.mod"),
    "ruby": (".rb", "Gemfile"),
    "php": (".php", "composer.json"),
}
# product -> (pin file, regex capturing the version)
PINS = [
    ("python", ".python-version", r"^\s*(?:python-)?(\d+(?:\.\d+)*)"),
    ("nodejs", ".nvmrc", r"^\s*v?(\d+(?:\.\d+)*)"),
    ("nodejs", ".node-version", r"^\s*v?(\d+(?:\.\d+)*)"),
    ("go", "go.mod", r"(?m)^go\s+(\d+(?:\.\d+)*)"),
    ("ruby", ".ruby-version", r"^\s*(?:ruby-)?(\d+(?:\.\d+)*)"),
]
DOCKER_IMAGES = {"python": "python", "node": "nodejs", "golang": "go", "ruby": "ruby", "php": "php"}
DOCKER_FROM = re.compile(r"(?im)^\s*FROM\s+(?:--\S+\s+)*(?:\S+/)?(python|node|golang|ruby|php):(\d+(?:\.\d+)*)")
# product -> version command. Run from the tool's own folder: php reads php.ini and go honors go.mod
# toolchain lines from the current folder, so the audited repo must not be the cwd.
VERSION_CMDS = {"python": ["python", "--version"], "nodejs": ["node", "--version"], "go": ["go", "version"],
                "ruby": ["ruby", "--version"], "php": ["php", "--version"]}


def _ints(version):
    return tuple(int(n) for n in re.findall(r"\d+", version))


def evaluate(product, version, cycles, today):
    """(severity, message) for one runtime version against endoflife.date cycles (newest first)."""
    v = _ints(version)
    matches = [c for c in cycles if _ints(str(c["cycle"])) == v[:len(_ints(str(c["cycle"])))]]
    if not matches:
        return "INFO", "not in endoflife.date data; check support status manually"
    cycle = max(matches, key=lambda c: len(_ints(str(c["cycle"]))))

    def ended(c):
        return c.get("eol") is True or (isinstance(c.get("eol"), str) and c["eol"] <= today)

    if ended(cycle):
        newest = next((c for c in cycles if not ended(c)), None)
        since = f" since {cycle['eol']}" if isinstance(cycle.get("eol"), str) else ""
        upgrade = f"; upgrade to {newest['cycle']} (latest {newest.get('latest')})" if newest else ""
        return "HIGH", f"end of life{since}, no more security fixes{upgrade}"
    latest = str(cycle.get("latest") or "")
    if latest and len(v) < len(_ints(latest)):
        return "INFO", f"supported; pin a full version to check patches (latest {latest})"
    if latest and _ints(latest) > v:
        return "MEDIUM", f"missing security and bug fixes; update to {latest}"
    return "INFO", "supported and up to date"


def _installed(product):
    exe = scan.find_tool(VERSION_CMDS[product][0])
    if not exe:
        return None
    try:
        r = subprocess.run([exe, *VERSION_CMDS[product][1:]], cwd=os.path.dirname(exe), capture_output=True,
                           encoding="utf-8", errors="replace", timeout=10)
    except Exception:
        return None
    m = re.search(r"\d+\.\d+(?:\.\d+)?", r.stdout + r.stderr)
    return m.group(0) if m else None


def _read(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read(100_000)
    except OSError:
        return ""


SKIP_DIRS = {"node_modules", "vendor", "venv", ".venv", "site-packages", "dist", "build", "__pycache__"}


def _project_files(repo, depth=2):
    """File names in the repo root and up to `depth` folders down, skipping vendored and hidden folders."""
    root_depth = repo.rstrip("\\/").count(os.sep)
    for folder, dirs, files in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        if folder.count(os.sep) - root_depth >= depth:
            dirs[:] = []
        yield from files


def detect(repo, installed=_installed):
    """(product, version, source) for runtimes the project pins, builds on, or uses."""
    repo = os.path.abspath(repo)
    names = os.listdir(repo)
    project = set(_project_files(repo))
    found = []
    for product, name, pattern in PINS:
        if name in names:
            m = re.search(pattern, _read(os.path.join(repo, name)))
            if m:
                found.append((product, m.group(1), name))
    for name in names:
        if name == "Dockerfile" or name.startswith("Dockerfile.") or name.endswith(".Dockerfile"):
            for image, version in DOCKER_FROM.findall(_read(os.path.join(repo, name))):
                found.append((DOCKER_IMAGES[image.lower()], version, name))
    pinned = {p for p, _, _ in found}
    for product, markers in USES.items():
        used = any(n in markers or os.path.splitext(n)[1] in markers for n in project)
        if used and product not in pinned:
            version = installed(product)
            if version:
                found.append((product, version, "installed"))
    return list(dict.fromkeys(found))


def _fetch(product):
    if product not in USES:  # fixed https URL, product only from our own list: no file:// or host control
        raise ValueError(product)
    url = f"https://endoflife.date/api/{product}.json"
    # nosemgrep: dynamic-urllib-use-detected (constant https host, product validated above)
    with urllib.request.urlopen(url, timeout=10) as r:  # nosec B310
        return json.load(r)


def runtime_findings(repo, fetch=_fetch, installed=_installed, today=None):
    """(severity, text) pairs for every runtime the project uses. Offline = one INFO note per runtime."""
    today = today or datetime.date.today().isoformat()
    cache, findings = {}, []
    for product, version, source in detect(repo, installed):
        if product not in cache:
            try:
                cache[product] = fetch(product)
            except Exception:
                cache[product] = None
        if cache[product] is None:
            findings.append(("INFO", f"language update check for {product} skipped (offline or endoflife.date unavailable)"))
            continue
        severity, message = evaluate(product, version, cache[product], today)
        findings.append((severity, f"{product} {version} ({source}): {message}"))
    return findings
