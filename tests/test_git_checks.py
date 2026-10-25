import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "hooks"))

import audit  # noqa: E402
import guard  # noqa: E402
import scan  # noqa: E402

NOREPLY = "1+someone@users.noreply.github.com"
PERSONAL = "someone@example.com"
# Assembled at runtime so this file never contains a real-looking secret.
AWS = "AKIA" + "B" * 16


class Repo:
    def __init__(self, email=NOREPLY):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name)
        self.git("init", "-q")
        self.git("config", "user.email", email)
        self.git("config", "user.name", "Tester")
        self.git("config", "commit.gpgsign", "false")

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=self.path, check=True, capture_output=True, text=True)

    def write(self, rel, text):
        p = self.path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")

    def commit(self, rel, text, msg="c"):
        self.write(rel, text)
        self.git("add", "-f", rel)
        self.git("commit", "-q", "-m", msg)

    def close(self):
        self.tmp.cleanup()


class DiffTests(unittest.TestCase):
    def test_added_secret_line_numbers(self):
        diff = "\n".join([
            "commit abcdef1234567890",
            "diff --git a/app.py b/app.py",
            "--- a/app.py",
            "+++ b/app.py",
            "@@ -1,0 +5,2 @@",
            "+x = 1",
            f"+key = '{AWS}'",
            "-old = 'gone'",
        ])
        findings = scan.diff_secret_findings(diff)
        self.assertEqual(len(findings), 1)
        self.assertIn("app.py:6:", findings[0])
        self.assertIn("abcdef1234", findings[0])
        self.assertIn("[aws-key]", findings[0])

    def test_removed_lines_and_code_rules_ignored(self):
        diff = "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1 +1 @@\n" \
               f"-k = '{AWS}'\n+y = eval(x)\n"  # sekyu: ignore -- test fixture
        self.assertEqual(scan.diff_secret_findings(diff), [])

    def test_plus_plus_content_is_not_a_header(self):
        diff = "diff --git a/a.txt b/a.txt\n--- a/a.txt\n+++ b/a.txt\n@@ -0,0 +1,2 @@\n" \
               f"+++ looks like a header\n+{AWS}\n"
        self.assertEqual(len(scan.diff_secret_findings(diff)), 1)

    def test_linear_time(self):
        diff = "diff --git a/a b/a\n--- a/a\n+++ b/a\n@@ -0,0 +1 @@\n+" + "a" * 500000
        start = time.perf_counter()
        scan.diff_secret_findings(diff)
        self.assertLess(time.perf_counter() - start, 1.0)


class GuardGitTests(unittest.TestCase):
    def setUp(self):
        self.repo = Repo()

    def tearDown(self):
        self.repo.close()

    def check(self, cmd):
        return guard.check_git(cmd, str(self.repo.path))

    def test_non_git_command_skipped(self):
        with mock.patch("subprocess.run") as run:
            self.assertIsNone(guard.check_git("ls -la", "."))
            run.assert_not_called()

    def test_personal_email_blocks_commit_and_push(self):
        self.repo.git("config", "user.email", PERSONAL)
        for cmd in ("git commit -m 'x'", "git push origin main", "git add . && git commit"):
            with self.subTest(cmd=cmd):
                self.assertIn("noreply", self.check(cmd))

    def test_noreply_clean_commit_allowed(self):
        self.repo.write("a.py", "x = 1\n")
        self.repo.git("add", "a.py")
        self.assertIsNone(self.check("git commit -m 'x'"))
        self.assertIsNone(self.check("git push"))

    def test_staged_secret_blocks_commit(self):
        self.repo.write("a.py", f"key = '{AWS}'\n")
        self.repo.git("add", "a.py")
        reason = self.check('git commit -m "add key"')
        self.assertIn("aws-key", reason)
        self.assertIn("a.py:1", reason)

    def test_commit_all_scans_unstaged_tracked_changes(self):
        self.repo.commit("a.py", "x = 1\n")
        self.repo.write("a.py", f"x = 1\nkey = '{AWS}'\n")
        self.assertIsNone(self.check("git commit -m x"))
        self.assertIn("aws-key", self.check("git commit -am x"))

    def test_fails_open_on_git_error(self):
        with mock.patch("subprocess.run", side_effect=FileNotFoundError):
            self.assertIsNone(guard.check_git("git commit -m x", "."))
        with mock.patch("subprocess.run", side_effect=subprocess.TimeoutExpired("git", 4)):
            self.assertIsNone(guard.check_git("git push", "."))

    def test_main_blocks_via_hook(self):
        self.repo.git("config", "user.email", PERSONAL)
        payload = {"tool_input": {"command": "git commit -m x"}, "cwd": str(self.repo.path)}
        r = subprocess.run([sys.executable, str(ROOT / "hooks" / "guard.py")],
                           input=json.dumps(payload), capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)
        self.assertIn("noreply", r.stderr)

    def test_main_stderr_utf8_on_cp1252_console(self):
        self.repo.git("config", "user.email", "┌box@example.com")
        payload = {"tool_input": {"command": "git push"}, "cwd": str(self.repo.path)}
        r = subprocess.run([sys.executable, str(ROOT / "hooks" / "guard.py")], input=json.dumps(payload).encode(),
                           capture_output=True, env=dict(os.environ, PYTHONIOENCODING="cp1252"))
        self.assertEqual(r.returncode, 2)
        self.assertIn("┌box@example.com", r.stderr.decode("utf-8"))


class AuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo = r = Repo(email=PERSONAL)
        r.commit(".gitignore", "build/\n")
        r.commit("config.py", f"key = '{AWS}'\n", "leak")
        r.commit("config.py", "import os\nkey = os.environ['KEY']\n", "fix")
        r.commit("app.py", "y = eval(x)\n")  # sekyu: ignore -- test fixture
        r.commit(".env", "A=1\n")
        r.commit(".env.example", "A=\n")
        r.commit("deploy.pem", "x\n")
        r.commit("build/out.txt", "x\n")
        r.git("config", "user.email", NOREPLY)
        r.commit("ok.txt", "fine\n")
        cls.result = audit.audit(str(r.path), external=False)
        cls.text = audit.report(cls.result)

    @classmethod
    def tearDownClass(cls):
        cls.repo.close()

    def joined(self, severity):
        return "\n".join(self.result[severity])

    def test_secret_in_history_is_high(self):
        self.assertIn("aws-key", self.joined("HIGH"))
        self.assertIn("config.py:1", self.joined("HIGH"))

    def test_risky_code_is_medium(self):
        self.assertIn("app.py:1: [eval]", self.joined("MEDIUM"))

    def test_emails(self):
        self.assertIn(PERSONAL, self.joined("MEDIUM"))
        self.assertNotIn(NOREPLY, self.joined("MEDIUM"))
        self.assertIn(NOREPLY, self.joined("INFO"))

    def test_sensitive_files(self):
        high = self.joined("HIGH")
        self.assertIn(".env", high)
        self.assertIn("deploy.pem", high)
        self.assertNotIn(".env.example", high)

    def test_ignored_but_tracked(self):
        self.assertIn("build/out.txt", self.joined("MEDIUM"))

    def test_report_grouped(self):
        self.assertLess(self.text.index("HIGH"), self.text.index("MEDIUM"))
        self.assertLess(self.text.index("MEDIUM"), self.text.index("INFO"))

    def test_read_only(self):
        status = self.repo.git("status", "--porcelain").stdout
        self.assertEqual(status, "")

    def test_not_a_repo(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertIn("not a git repository", audit.report(audit.audit(d)))


NPM_JSON = {
    "vulnerabilities": {
        "lodash": {"severity": "high", "range": "<4.17.21", "fixAvailable": {"name": "lodash", "version": "4.17.21"}},
        "minimist": {"severity": "low", "range": "<1.2.6", "fixAvailable": False},
    }
}
LOCK_JSON = {"packages": {"node_modules/lodash": {"version": "4.17.15"}}}
PIP_JSON = {"dependencies": [
    {"name": "requests", "version": "2.19.0", "vulns": [{"id": "PYSEC-2018-28", "fix_versions": ["2.20.0"]}]},
    {"name": "flask", "version": "3.0.0", "vulns": []},
]}


OSV_JSON = {"results": [{"source": {"path": "/r/package-lock.json"}, "packages": [
    {"package": {"name": "lodash", "version": "4.17.15", "ecosystem": "npm"},
     "vulnerabilities": [{"id": "GHSA-x"}, {"id": "GHSA-y"}],
     "groups": [{"ids": ["GHSA-x"], "max_severity": "9.1"}, {"ids": ["GHSA-y"], "max_severity": "5.3"}]},
    {"package": {"name": "serde", "version": "1.0.0", "ecosystem": "crates.io"},
     "vulnerabilities": [{"id": "RUSTSEC-1"}], "groups": [{"ids": ["RUSTSEC-1"], "max_severity": ""}]},
]}]}
SEMGREP_JSON = {"results": [
    {"check_id": "python.lang.security.audit.subprocess-shell-true", "path": "app.py", "start": {"line": 3},
     "extra": {"severity": "ERROR", "message": "Found shell=True.\nMore text."}},
    {"check_id": "js.warn", "path": "web/a.js", "start": {"line": 1}, "extra": {"severity": "WARNING", "message": "meh"}},
], "errors": []}


def fake_run(outputs, calls):
    def run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        name = Path(cmd[0]).stem
        if isinstance(outputs[name], Exception):
            raise outputs[name]
        out = outputs[name]
        return subprocess.CompletedProcess(cmd, 1, "" if out == "" else json.dumps(out), "")
    return run


class DependencyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.calls = []

    def tearDown(self):
        self.tmp.cleanup()

    def deps(self, outputs, found=("npm", "pip-audit")):
        which = lambda name: f"/bin/{name}" if name in found else None  # noqa: E731
        with mock.patch("shutil.which", side_effect=which), \
                mock.patch("subprocess.run", side_effect=fake_run(outputs, self.calls)):
            return audit.dependency_findings(str(self.dir))

    def text(self, findings, severity=None):
        return "\n".join(t for s, t in findings if severity in (None, s))

    def test_no_manifests_runs_nothing(self):
        self.assertEqual(self.deps({}), [])
        self.assertEqual(self.calls, [])

    def test_npm_audit(self):
        (self.dir / "package-lock.json").write_text(json.dumps(LOCK_JSON))
        found = self.deps({"npm": NPM_JSON})
        high = self.text(found, "HIGH")
        self.assertIn("lodash", high)
        self.assertIn("4.17.15", high)
        self.assertIn("4.17.21", high)
        self.assertIn("minimist", self.text(found, "MEDIUM"))
        cmd, kwargs = self.calls[0]
        self.assertEqual(cmd[1:], ["audit", "--json"])
        self.assertEqual(kwargs["timeout"], 60)

    def test_pip_audit_requirements(self):
        (self.dir / "requirements.txt").write_text("requests==2.19.0\n")
        (self.dir / "requirements-dev.txt").write_text("\n")
        found = self.deps({"pip-audit": PIP_JSON})
        high = self.text(found, "HIGH")
        self.assertIn("requests 2.19.0", high)
        self.assertIn("PYSEC-2018-28", high)
        self.assertIn("2.20.0", high)
        self.assertNotIn("flask", self.text(found))
        cmd = self.calls[0][0]
        self.assertEqual(cmd[1:3], ["-f", "json"])
        self.assertIn("requirements.txt", cmd)
        self.assertIn("requirements-dev.txt", cmd)

    def test_pip_audit_never_resolves(self):
        # Resolution makes pip build packages, which runs code from the audited repo.
        (self.dir / "requirements.txt").write_text("requests[security]==2.19.0 ; python_version >= '3'  # pinned\n")
        self.deps({"pip-audit": PIP_JSON})
        cmd = self.calls[0][0]
        self.assertIn("--disable-pip", cmd)
        self.assertIn("--no-deps", cmd)

    def test_unsafe_requirements_skipped(self):
        for line in ("./pkg", "-e .", "--index-url https://evil/simple", "git+https://x/y.git",
                     "requests>=2", "pkg @ https://x/p.whl", "-r other.txt", "pkg==1.0 --hash=sha256:ab"):
            with self.subTest(line=line):
                self.calls.clear()
                (self.dir / "requirements.txt").write_text("flask==2.0.0\n" + line + "\n")
                found = self.deps({"pip-audit": PIP_JSON})
                self.assertEqual(self.calls, [])
                self.assertIn("requirements.txt skipped", self.text(found, "INFO"))

    def test_pyproject_not_run(self):
        (self.dir / "pyproject.toml").write_text("[project]\n")
        found = self.deps({"pip-audit": {"dependencies": []}})
        self.assertEqual(self.calls, [])
        self.assertIn("pyproject.toml", self.text(found, "INFO"))

    def test_missing_tool_is_note(self):
        (self.dir / "yarn.lock").write_text("")
        (self.dir / "requirements.txt").write_text("requests==2.19.0\n")
        found = self.deps({}, found=())
        self.assertEqual(self.calls, [])
        info = self.text(found, "INFO")
        self.assertIn("not run: install npm", info)
        self.assertIn("not run: install pip-audit", info)

    def test_osv_scanner_preferred_for_all_ecosystems(self):
        (self.dir / "package-lock.json").write_text(json.dumps(LOCK_JSON))
        (self.dir / "requirements.txt").write_text("requests==2.19.0\n")
        found = self.deps({"osv-scanner": OSV_JSON}, found=("osv-scanner", "npm", "pip-audit"))
        self.assertEqual([Path(c[0][0]).stem for c in self.calls], ["osv-scanner"])  # replaces npm/pip-audit
        cmd = self.calls[0][0]
        for arg in ("scan", "source", "--format", "json", "-r", "--config"):
            self.assertIn(arg, cmd)  # --config: ignore the repo's own osv-scanner.toml suppressions
        self.assertIn("npm lodash 4.17.15: GHSA-x", self.text(found, "HIGH"))
        medium = self.text(found, "MEDIUM")
        self.assertIn("GHSA-y", medium)
        self.assertIn("crates.io serde 1.0.0: RUSTSEC-1", medium)

    def test_osv_scanner_covers_other_lockfiles(self):
        (self.dir / "Cargo.lock").write_text("")
        self.deps({"osv-scanner": {"results": []}}, found=("osv-scanner",))
        self.assertEqual(len(self.calls), 1)

    def test_osv_scanner_no_output_is_quiet(self):
        (self.dir / "go.mod").write_text("module x\n")
        self.assertEqual(self.deps({"osv-scanner": ""}, found=("osv-scanner",)), [])  # exit 128, empty stdout

    def test_tool_failure_fails_open(self):
        (self.dir / "pnpm-lock.yaml").write_text("")
        (self.dir / "requirements.txt").write_text("")
        found = self.deps({"npm": subprocess.TimeoutExpired("npm", 60), "pip-audit": "not json {"})
        self.assertEqual([s for s, _ in found], ["INFO", "INFO"])


class SemgrepAuditTests(unittest.TestCase):
    def run_semgrep(self, output, found=True):
        calls = []
        which = lambda name: f"/bin/{name}" if found else None  # noqa: E731
        with mock.patch("shutil.which", side_effect=which), \
                mock.patch("subprocess.run", side_effect=fake_run({"semgrep": output}, calls)):
            return audit.semgrep_findings(tempfile.gettempdir()), calls

    def test_taint_packs_and_severity(self):
        found, calls = self.run_semgrep(SEMGREP_JSON)
        cmd = calls[0][0]
        for arg in ("p/security-audit", "p/command-injection", "--json", "--disable-nosem"):
            self.assertIn(arg, cmd)  # --disable-nosem: an audited repo must not silence its own findings
        self.assertIn(("HIGH", "app.py:3: [semgrep python.lang.security.audit.subprocess-shell-true] Found shell=True."),  # sekyu: ignore -- fixture
                      found)
        self.assertIn("MEDIUM", [s for s, t in found if "web/a.js:1" in t])

    def test_missing_semgrep_is_note(self):
        found, calls = self.run_semgrep({}, found=False)
        self.assertEqual(calls, [])
        self.assertIn("install semgrep", found[0][1])


def hostile_repo():
    """Repo whose own .git/config runs commands on read-only git use (fsmonitor, textconv). Harmless marker files."""
    r = Repo()
    r.commit("a.txt", "one\n")
    r.commit(".gitattributes", "*.txt diff=evil\n")
    r.commit("a.txt", "two\n")
    script = r.path / "fsmon.sh"
    script.write_text(f'#!/bin/sh\necho ran >> "{(r.path / "PROOF_fsmonitor").as_posix()}"\n', encoding="utf-8")
    os.chmod(script, 0o700)  # owner-only; executable so git can run it
    r.git("config", "core.fsmonitor", script.as_posix())
    r.git("config", "diff.evil.textconv", f"sh -c 'echo ran >> \"{(r.path / 'PROOF_textconv').as_posix()}\"; cat'")
    return r


class HostileGitConfigTests(unittest.TestCase):
    def setUp(self):
        self.repo = hostile_repo()

    def tearDown(self):
        self.repo.close()

    def proofs(self):
        return sorted(p.name for p in self.repo.path.glob("PROOF_*"))

    def test_audit_never_runs_repo_config_commands(self):
        result = audit.audit(str(self.repo.path), external=False)
        self.assertEqual(self.proofs(), [])
        high = "\n".join(result["HIGH"])
        self.assertIn("core.fsmonitor", high)
        self.assertIn("diff.evil.textconv", high)

    def test_audit_reports_git_hooks(self):
        hook = self.repo.path / ".git" / "hooks" / "pre-commit"
        hook.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        result = audit.audit(str(self.repo.path), external=False)
        self.assertTrue(any("pre-commit" in m for m in result["MEDIUM"]), result["MEDIUM"])
        self.assertFalse(any(".sample" in m for m in result["MEDIUM"]))

    def test_guard_blocks_commit_and_runs_nothing(self):
        self.repo.write("a.txt", "three\n")
        self.repo.git("-c", "core.fsmonitor=false", "add", "a.txt")
        reason = guard.check_git("git commit -m x", str(self.repo.path))
        self.assertIsNotNone(reason)
        self.assertIn("core.fsmonitor", reason)
        self.assertEqual(self.proofs(), [])

    def test_safe_config_values_allowed(self):
        r = Repo()
        try:
            r.commit("a.txt", "x\n")
            r.git("config", "core.fsmonitor", "false")
            r.git("config", "alias.st", "status")
            self.assertEqual(guard.risky_git_config(str(r.path)), [])
            r.git("config", "alias.pwn", "!sh -c id")
            self.assertEqual(guard.risky_git_config(str(r.path)), ["alias.pwn=!sh -c id"])
        finally:
            r.close()


class AuditExternalTests(unittest.TestCase):
    def test_external_checks_merged(self):
        with tempfile.TemporaryDirectory() as d:
            subprocess.run(["git", "init", "-q", d], check=True)
            with mock.patch.object(audit, "semgrep_findings", return_value=[("HIGH", "rce here")]) as sg, \
                    mock.patch.object(audit.runtimes, "runtime_findings", return_value=[("HIGH", "python 3.8 eol")]) as rt:
                result = audit.audit(d, external=True)
                sg.assert_called_once()
                rt.assert_called_once()
                self.assertIn("rce here", result["HIGH"])
                self.assertIn("python 3.8 eol", result["HIGH"])
                audit.audit(d, external=False)
                sg.assert_called_once()  # not called again


if __name__ == "__main__":
    unittest.main()
