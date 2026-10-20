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
        cls.result = audit.audit(str(r.path))
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


def fake_run(outputs, calls):
    def run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        name = Path(cmd[0]).stem
        if isinstance(outputs[name], Exception):
            raise outputs[name]
        return subprocess.CompletedProcess(cmd, 1, json.dumps(outputs[name]), "")
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

    def test_tool_failure_fails_open(self):
        (self.dir / "pnpm-lock.yaml").write_text("")
        (self.dir / "requirements.txt").write_text("")
        found = self.deps({"npm": subprocess.TimeoutExpired("npm", 60), "pip-audit": "not json {"})
        self.assertEqual([s for s, _ in found], ["INFO", "INFO"])


if __name__ == "__main__":
    unittest.main()
