"""PreToolUse hook: block dangerous shell commands before they run.

Checks split the command into segments and tokens instead of using one big regex,
so run time stays linear on hostile input (no ReDoS -> no hook timeout -> no fail-open).
"""
import json
import re
import subprocess
import sys

import scan

DOWNLOAD = re.compile(r"\b(curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b", re.I)
SHELL = re.compile(r"\s*(sudo\s+)?((ba|z|da)?sh|iex|Invoke-Expression)\b", re.I)
IEX_OF_DOWNLOAD = re.compile(r"\b(iex|Invoke-Expression)\s*\(\s*(iwr|irm|Invoke-WebRequest|Invoke-RestMethod|curl|wget)\b", re.I)
DELETE_CMDS = {"rm", "remove-item", "ri", "del", "rd", "rmdir"}
PROTECTED = {"", "~", "$home", "$env:userprofile", "${home}"}

CHMOD_777 = re.compile(r"\bchmod\s+(-R\s+)?777\b")
ENV_TEMPLATES = {"example", "sample", "template", "dist"}
# Commit message text is data, not a command: blank it so "curl x | sh" in a message is not blocked.
COMMIT_MESSAGE = re.compile(r"""(\s(?:-m|--message)\s*)("[^"]*"|'[^']*')""")


def _pipes_download_to_shell(cmd):
    segments = cmd.split("|")
    return any(DOWNLOAD.search(left) and SHELL.match(right) for left, right in zip(segments, segments[1:]))


def _is_recursive_flag(arg):
    a = arg.lower()
    if a in ("--recursive", "-force", "--force"):
        return a == "--recursive"
    return a.startswith("-rec") or (a.startswith("-") and not a.startswith("--") and a[1:].isalpha() and "r" in a[1:])


def _is_protected_target(arg):
    a = arg.lower().rstrip("*").rstrip("/\\")
    return a in PROTECTED or re.fullmatch(r"[a-z]:", a) is not None


def _segments(cmd):
    return [segment.split() for segment in re.split(r"[;&|]", cmd)]


def _git_args(tokens, subcommand):
    for i in range(len(tokens) - 1):
        if tokens[i] == "git" and tokens[i + 1] == subcommand:
            return tokens[i + 2:]
    return []


def _is_force_arg(a):
    if a.startswith("--"):
        return a.startswith("--force") and not a.startswith("--force-with-lease")
    if a.startswith("-"):
        return a[1:].isalpha() and "f" in a[1:]  # -f, -fu, -uf
    return a.startswith("+")  # +main refspec forces that ref


def _force_push(cmd):
    return any(_is_force_arg(a) for tokens in _segments(cmd) for a in _git_args(tokens, "push"))


def _is_env_file(arg):
    name = arg.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return name == ".env" or (name.startswith(".env.") and name.rsplit(".", 1)[-1] not in ENV_TEMPLATES)


def _adds_env(cmd):
    return any(_is_env_file(a) for tokens in _segments(cmd) for a in _git_args(tokens, "add"))


def _deletes_root_or_home(cmd):
    for tokens in _segments(cmd):
        starts = [i for i, t in enumerate(tokens) if t.lower() in DELETE_CMDS]
        if not starts:
            continue
        args = tokens[starts[0] + 1:]
        flags = [a for a in args if a.startswith("-")]
        targets = [a for a in args if not a.startswith("-")]
        if any(map(_is_recursive_flag, flags)) and any(map(_is_protected_target, targets)):
            return True
    return False


def check_command(cmd):
    cmd = COMMIT_MESSAGE.sub(r'\1""', cmd)
    if _pipes_download_to_shell(cmd) or IEX_OF_DOWNLOAD.search(cmd):
        return "running a downloaded script executes unreviewed code"
    if _deletes_root_or_home(cmd):
        return "recursive delete of a drive root or home directory"
    if _force_push(cmd):
        return "force push can destroy remote history; use --force-with-lease"
    if CHMOD_777.search(cmd):
        return "chmod 777 makes files world-writable"
    if _adds_env(cmd):
        return "committing .env leaks secrets"
    return None


def _git_runs(cmd, subcommand):
    return any(t == "git" and nxt == subcommand for tokens in _segments(cmd) for t, nxt in zip(tokens, tokens[1:]))


def _git(cwd, *args):
    # 4 s each, at most 2 calls: stays inside the 10 s hook timeout.
    r = subprocess.run(["git", *args], cwd=cwd, capture_output=True, encoding="utf-8", errors="replace", timeout=4)
    if r.returncode != 0:
        raise RuntimeError(r.stderr)
    return r.stdout


def _commit_all(cmd):
    return any(a == "--all" or (a.startswith("-") and not a.startswith("--") and a[1:].isalpha() and "a" in a[1:])
               for tokens in _segments(cmd) for a in _git_args(tokens, "commit"))


def check_git(cmd, cwd=None):
    """Before git commit/push: require a GitHub noreply identity and no secrets in what is being committed."""
    cmd = COMMIT_MESSAGE.sub(r'\1""', cmd)
    committing = _git_runs(cmd, "commit")
    if not (committing or _git_runs(cmd, "push")):
        return None
    try:
        email = _git(cwd, "config", "user.email").strip()
        if not email.lower().endswith("@users.noreply.github.com"):
            return (f"git user.email is '{email}', not a GitHub noreply address, so it would be published in "
                    "commit history. Ask the user whether to set "
                    "'git config user.email <id>+<user>@users.noreply.github.com' first")
        if committing:
            target = ["HEAD"] if _commit_all(cmd) else ["--cached"]
            findings = scan.diff_secret_findings(_git(cwd, "diff", *target, "--unified=0", "--no-color", "--no-ext-diff"))
            if findings:
                return "secrets in the changes being committed; remove them first:\n" + "\n".join(findings[:20])
    except Exception:
        return None  # fail open: no git, not a repo, no HEAD, timeout
    return None


def main():
    try:
        data = json.load(sys.stdin)
        cmd = data.get("tool_input", {}).get("command", "")
        reason = check_command(cmd) or check_git(cmd, data.get("cwd") or None)
    except Exception:
        return 0  # fail open on malformed input
    if reason:
        print(f"sekyu blocked: {reason}. Ask the user to run it themselves if intended.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
