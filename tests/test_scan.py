import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "hooks"))

import scan  # noqa: E402

# Fake secrets are assembled at runtime so this file never contains a real-looking one.
SECRETS = {
    "aws-key": "key = " + "AKIA" + "A" * 16,
    "private-key": "-----BEGIN RSA " + "PRIVATE KEY-----",
    "github-token": "t = " + "ghp_" + "a" * 36,
    "anthropic-key": "k = " + "sk-ant-" + "a" * 30,
    "hardcoded-secret": 'password = "' + "hunter2" * 2 + '"',
}

CODE = {
    "eval": ("app.py", "y = eval(x)"),
    "exec": ("app.py", "exec(x)"),
    "shell-true": ("app.py", "subprocess.run(c, shell=True)"),
    "os-system": ("app.py", "os.system(c)"),
    "pickle": ("app.py", "pickle.loads(b)"),
    "yaml-load": ("app.py", "yaml.load(f)"),
    "inner-html": ("app.js", "el.innerHTML = s"),
    "dangerously-set-html": ("app.jsx", "<div dangerouslySetInnerHTML={{__html: s}} />"),
    "tls-off": ("app.py", "requests.get(u, verify=False)"),
}

SQL = [
    'cur.execute("SELECT * FROM t WHERE id=" + uid)',
    'cur.execute(f"SELECT {x}")',
    'cur.execute("SELECT * FROM t WHERE id={}".format(uid))',
]


def ids(findings):
    return [f.split("[", 1)[1].split("]", 1)[0] for f in findings]


def run_scan(path, **tool_input):
    env = dict(os.environ, SEKYU_NO_EXTERNAL="1")
    payload = json.dumps({"tool_input": {"file_path": str(path), **tool_input}})
    return subprocess.run(
        [sys.executable, str(ROOT / "hooks" / "scan.py")],
        input=payload, capture_output=True, text=True, env=env,
    )


class ToolLookupTests(unittest.TestCase):
    """External tools must never be launched from the folder being scanned (CWE-427 binary planting)."""

    def test_rejects_tool_found_in_cwd(self):
        for found in (os.path.join(os.getcwd(), "semgrep.exe"), ".\\semgrep.EXE", "semgrep"):
            with self.subTest(found=found), mock.patch.object(scan.shutil, "which", return_value=found):
                self.assertIsNone(scan.find_tool("semgrep"))

    def test_accepts_tool_outside_cwd(self):
        outside = os.path.join(tempfile.gettempdir(), "elsewhere", "semgrep.exe")
        with mock.patch.object(scan.shutil, "which", return_value=outside):
            self.assertEqual(scan.find_tool("semgrep"), outside)

    def test_drive_root_cwd_still_finds_installed_tools(self):
        root = os.path.abspath(os.sep)  # e.g. C:\ : every installed tool is "under" it
        installed = os.path.join(root, "Python314", "python.exe")
        planted = os.path.join(root, "semgrep.exe")
        with mock.patch.object(scan.os, "getcwd", return_value=root):
            with mock.patch.object(scan.shutil, "which", return_value=installed):
                self.assertEqual(scan.find_tool("python"), installed)
            with mock.patch.object(scan.shutil, "which", return_value=planted):
                self.assertIsNone(scan.find_tool("semgrep"))

    @unittest.skipUnless(os.name == "nt", "Windows searches the current folder for executables")
    def test_planted_exe_never_runs(self):
        with tempfile.TemporaryDirectory() as d:
            for name in ("git.exe", "semgrep.exe"):
                shutil.copy(r"C:\Windows\System32\whoami.exe", os.path.join(d, name))
            env = {k: v for k, v in os.environ.items() if k.lower() != "nodefaultcurrentdirectoryinexepath"}
            code = ("import sys; sys.path.insert(0, sys.argv[1]); import scan, guard; "
                    "print(scan.find_tool('semgrep')); print(guard._git(None, '--version'))")
            r = subprocess.run([sys.executable, "-c", code, str(ROOT / "hooks")], cwd=d, env=env,
                               capture_output=True, text=True)
            self.assertNotIn(d.lower(), r.stdout.lower())
            self.assertIn("git version", r.stdout)


class BuiltinTests(unittest.TestCase):
    def setUp(self):
        os.environ["SEKYU_NO_EXTERNAL"] = "1"

    def test_secrets_any_file(self):
        for rule, line in SECRETS.items():
            with self.subTest(rule=rule):
                self.assertEqual(ids(scan.builtin_findings("notes.md", line)), [rule])

    def test_code_rules(self):
        for rule, (path, line) in CODE.items():
            with self.subTest(rule=rule):
                self.assertEqual(ids(scan.builtin_findings(path, line)), [rule])

    def test_sql_concat(self):
        for line in SQL:
            with self.subTest(line=line):
                self.assertEqual(ids(scan.builtin_findings("app.py", line)), ["sql-concat"])

    def test_docs_not_code_scanned(self):
        self.assertEqual(scan.builtin_findings("README.md", "eval(x)\nel.innerHTML = s"), [])

    def test_safe_yaml(self):
        for line in ("yaml.load(f, Loader=yaml.SafeLoader)", "yaml.load(open(f), Loader=yaml.SafeLoader)",
                     "yaml.load(f, Loader=yaml.CSafeLoader)"):
            with self.subTest(line=line):
                self.assertEqual(scan.builtin_findings("app.py", line), [])

    def test_unsafe_yaml_loader(self):
        for line in ("yaml.load(f, Loader=yaml.Loader)", "yaml.unsafe_load(f)"):
            with self.subTest(line=line):
                self.assertEqual(ids(scan.builtin_findings("app.py", line)), ["yaml-load"])

    def test_unquoted_secrets_in_config(self):
        cases = [(".env", "API_KEY=" + "abc123" * 3), ("config.yaml", "api_key: " + "sk_live_" + "x" * 12),
                 ("app.ini", "db_password = " + "hunter2" * 2), (".env.local", "TOKEN=" + "z" * 20)]
        for path, line in cases:
            with self.subTest(path=path):
                self.assertEqual(ids(scan.builtin_findings(path, line)), ["hardcoded-secret"])

    def test_unquoted_placeholders_ok(self):
        cases = [(".env", "API_KEY=${API_KEY}"), ("config.yaml", "password: <set-me-in-env>"),
                 (".env.example", "API_KEY=your-key-goes-here"), ("app.py", "token = get_token_from_env()")]
        for path, line in cases:
            with self.subTest(path=path):
                self.assertEqual(scan.builtin_findings(path, line), [])

    def test_more_source_exts(self):
        for ext in (".vue", ".svelte", ".html", ".kt", ".rs", ".c"):
            with self.subTest(ext=ext):
                self.assertEqual(ids(scan.builtin_findings("app" + ext, "el.innerHTML = s")), ["inner-html"])

    def test_param_sql(self):
        self.assertEqual(scan.builtin_findings("app.py", 'cur.execute("SELECT * FROM t WHERE id=%s", (uid,))'), [])

    def test_ignore_marker(self):
        self.assertEqual(scan.builtin_findings("app.py", "eval(x)  # sekyu: ignore"), [])

    def test_line_numbers(self):
        findings = scan.builtin_findings("app.py", "a = 1\nb = 2\neval(x)")
        self.assertTrue(findings[0].startswith("app.py:3: [eval]"), findings)


class MainTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)

    def write(self, name, data):
        p = Path(self.dir.name) / name
        (p.write_bytes if isinstance(data, bytes) else p.write_text)(data)
        return p

    def test_main_findings(self):
        r = run_scan(self.write("bad.py", "eval(x)\n"))
        self.assertEqual(r.returncode, 2)
        self.assertIn("[eval]", r.stderr)

    def test_main_clean(self):
        r = run_scan(self.write("ok.py", "x = 1\n"))
        self.assertEqual((r.returncode, r.stderr), (0, ""))

    def test_edit_ignores_untouched_lines(self):
        path = self.write("legacy.py", "eval(old)\nx = 1\n")
        self.assertEqual(run_scan(path, old_string="x = 0", new_string="x = 1").returncode, 0)

    def test_edit_flags_new_lines(self):
        path = self.write("legacy.py", "x = 1\neval(new)\n")
        r = run_scan(path, old_string="pass", new_string="eval(new)")
        self.assertEqual(r.returncode, 2)

    def test_multiedit_flags_new_lines(self):
        path = self.write("legacy.py", "eval(new)\n")
        r = run_scan(path, edits=[{"old_string": "a", "new_string": "eval(new)"}])
        self.assertEqual(r.returncode, 2)

    def test_main_missing_file(self):
        self.assertEqual(run_scan(Path(self.dir.name) / "gone.py").returncode, 0)

    def test_main_binary(self):
        r = run_scan(self.write("blob.py", bytes(range(256)) * 10))
        self.assertEqual(r.returncode, 0)
        self.assertNotIn("Traceback", r.stderr)

    def test_main_large(self):
        r = run_scan(self.write("big.py", "eval(x)\n" + "#" * 2_000_000))
        self.assertEqual(r.returncode, 0)

    def run_raw(self, payload, **env):
        return subprocess.run([sys.executable, str(ROOT / "hooks" / "scan.py")], input=payload,
                              capture_output=True, env=dict(os.environ, SEKYU_NO_EXTERNAL="1", **env))

    def test_main_utf8_bom_stdin(self):
        path = self.write("bad.py", "eval(x)\n")  # sekyu: ignore -- test fixture
        r = self.run_raw(b"\xef\xbb\xbf" + json.dumps({"tool_input": {"file_path": str(path)}}).encode())
        self.assertEqual(r.returncode, 2)

    def test_main_stderr_utf8_on_cp1252_console(self):
        path = self.write("box┌.py", "eval(x)\n")  # sekyu: ignore -- test fixture
        r = self.run_raw(json.dumps({"tool_input": {"file_path": str(path)}}).encode(), PYTHONIOENCODING="cp1252")
        self.assertEqual(r.returncode, 2)
        self.assertIn("box┌.py", r.stderr.decode("utf-8"))


class ExternalTests(unittest.TestCase):
    def patch(self, which, run):
        p1 = mock.patch.object(scan.shutil, "which", which)
        p2 = mock.patch.object(scan.subprocess, "run", run)
        p1.start(), p2.start()
        self.addCleanup(mock.patch.stopall)

    def test_no_tools(self):
        run = mock.Mock()
        self.patch(lambda t: None, run)
        self.assertEqual(scan.external_findings("app.py"), [])
        run.assert_not_called()

    def test_semgrep_finding(self):
        done = subprocess.CompletedProcess([], 1, stdout="app.py:3 rule.x", stderr="")
        self.patch(lambda t: "/usr/bin/" + t if t == "semgrep" else None, mock.Mock(return_value=done))
        findings = scan.external_findings("app.py")
        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0].startswith("[semgrep]"))
        self.assertIn("rule.x", findings[0])

    def test_bandit_only_py(self):
        run = mock.Mock()
        self.patch(lambda t: "/usr/bin/" + t if t == "bandit" else None, run)
        self.assertEqual(scan.external_findings("app.js"), [])
        run.assert_not_called()

    def test_dash_path_not_a_flag(self):
        done = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        run = mock.Mock(return_value=done)
        self.patch(lambda t: "/usr/bin/" + t, run)
        scan.external_findings("--config=evil.py")
        for call in run.call_args_list:
            self.assertFalse(any(a.startswith("--config=evil") for a in call.args[0]))

    def test_error_exit_not_a_finding(self):
        done = subprocess.CompletedProcess([], 2, stdout="error: could not fetch p/default", stderr="")
        self.patch(lambda t: "/usr/bin/" + t, mock.Mock(return_value=done))
        self.assertEqual(scan.external_findings("app.py"), [])

    def test_gitleaks_finding(self):
        done = subprocess.CompletedProcess([], 3, stdout="leak in app.py:1", stderr="")
        self.patch(lambda t: "/usr/bin/" + t if t == "gitleaks" else None, mock.Mock(return_value=done))
        self.assertEqual(len(scan.external_findings("app.py")), 1)

    def test_decodes_utf8(self):
        run = mock.Mock(return_value=subprocess.CompletedProcess([], 0, stdout="", stderr=""))
        self.patch(lambda t: "/usr/bin/" + t if t == "semgrep" else None, run)
        scan.external_findings("app.py")
        self.assertEqual(run.call_args.kwargs.get("encoding"), "utf-8")

    def test_unexpected_error(self):
        err = UnicodeDecodeError("cp1252", b"\x9d", 0, 1, "bad")
        self.patch(lambda t: "/usr/bin/" + t, mock.Mock(side_effect=err))
        self.assertEqual(scan.external_findings("app.py"), [])

    def test_timeout(self):
        self.patch(lambda t: "/usr/bin/" + t, mock.Mock(side_effect=subprocess.TimeoutExpired("x", 60)))
        self.assertEqual(scan.external_findings("app.py"), [])

    def test_crash_no_output(self):
        done = subprocess.CompletedProcess([], 2, stdout="", stderr="")
        self.patch(lambda t: "/usr/bin/" + t, mock.Mock(return_value=done))
        self.assertEqual(scan.external_findings("app.py"), [])


if __name__ == "__main__":
    unittest.main()
