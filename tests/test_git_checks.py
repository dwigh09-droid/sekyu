import json
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


if __name__ == "__main__":
    unittest.main()
