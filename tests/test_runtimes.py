import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "hooks"))

import runtimes  # noqa: E402

TODAY = "2026-10-25"
EOL_DATA = {
    "python": [
        {"cycle": "3.13", "eol": "2029-10-31", "latest": "3.13.9"},
        {"cycle": "3.12", "eol": "2028-10-31", "latest": "3.12.12"},
        {"cycle": "3.8", "eol": "2024-10-07", "latest": "3.8.20"},
    ],
    "nodejs": [
        {"cycle": "22", "eol": "2027-04-30", "latest": "22.21.0"},
        {"cycle": "16", "eol": "2023-09-11", "latest": "16.20.2"},
    ],
    "go": [{"cycle": "1.25", "eol": False, "latest": "1.25.3"}, {"cycle": "1.21", "eol": True, "latest": "1.21.13"}],
    "ruby": [{"cycle": "3.4", "eol": "2028-03-31", "latest": "3.4.7"}],
}


def fetch(product):
    if product not in EOL_DATA:
        raise OSError("offline")
    return EOL_DATA[product]


class EvaluateTests(unittest.TestCase):
    def check(self, product, version):
        return runtimes.evaluate(product, version, fetch(product), TODAY)

    def test_end_of_life_is_high(self):
        severity, text = self.check("python", "3.8.10")
        self.assertEqual(severity, "HIGH")
        self.assertIn("end of life", text)
        self.assertIn("3.13", text)  # newest supported cycle suggested

    def test_eol_true_is_high(self):
        self.assertEqual(self.check("go", "1.21.5")[0], "HIGH")

    def test_missing_patch_is_medium(self):
        severity, text = self.check("python", "3.12.3")
        self.assertEqual(severity, "MEDIUM")
        self.assertIn("3.12.12", text)

    def test_latest_is_info(self):
        self.assertEqual(self.check("nodejs", "22.21.0")[0], "INFO")

    def test_numeric_not_string_compare(self):
        self.assertEqual(self.check("python", "3.12.12")[0], "INFO")  # "3.12.12" > "3.12.9" numerically

    def test_cycle_only_version(self):
        self.assertEqual(self.check("python", "3.8")[0], "HIGH")

    def test_unknown_cycle_is_info(self):
        self.assertEqual(self.check("python", "2.7.18")[0], "INFO")


class DetectTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, text):
        p = self.dir / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)

    def detect(self, installed=None):
        installed = installed or {}
        return runtimes.detect(str(self.dir), lambda product: installed.get(product))

    def test_pin_files(self):
        self.write(".python-version", "3.8.10\n")
        self.write(".nvmrc", "v16.20.0\n")
        self.write("go.mod", "module x\n\ngo 1.21\n")
        self.write(".ruby-version", "ruby-3.4.1\n")
        found = self.detect()
        self.assertIn(("python", "3.8.10", ".python-version"), found)
        self.assertIn(("nodejs", "16.20.0", ".nvmrc"), found)
        self.assertIn(("go", "1.21", "go.mod"), found)
        self.assertIn(("ruby", "3.4.1", ".ruby-version"), found)

    def test_dockerfile_base_images(self):
        self.write("Dockerfile", "FROM python:3.8-slim AS build\nFROM --platform=linux/amd64 node:16-alpine\nFROM golang:1.21.5\n")
        found = self.detect()
        self.assertIn(("python", "3.8", "Dockerfile"), found)
        self.assertIn(("nodejs", "16", "Dockerfile"), found)
        self.assertIn(("go", "1.21.5", "Dockerfile"), found)

    def test_installed_runtime_when_used_but_not_pinned(self):
        self.write("app.py", "print(1)\n")
        self.write("package.json", "{}\n")
        found = self.detect({"python": "3.12.3", "nodejs": "22.21.0", "ruby": "3.4.7"})
        self.assertIn(("python", "3.12.3", "installed"), found)
        self.assertIn(("nodejs", "22.21.0", "installed"), found)
        self.assertNotIn("ruby", [p for p, _, _ in found])  # project doesn't use Ruby

    def test_sources_in_subfolders(self):
        self.write("hooks/scan.py", "x = 1\n")
        self.write("node_modules/dep/index.js", "x\n")  # vendored code is not the project's runtime
        found = self.detect({"python": "3.14.0", "nodejs": "22.21.0"})
        self.assertIn(("python", "3.14.0", "installed"), found)
        self.assertNotIn("nodejs", [p for p, _, _ in found])

    def test_pin_wins_over_installed(self):
        self.write(".python-version", "3.8.10\n")
        found = self.detect({"python": "3.12.3"})
        self.assertEqual([f for f in found if f[0] == "python"], [("python", "3.8.10", ".python-version")])


class FindingsTests(unittest.TestCase):
    def test_findings_and_offline(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, ".python-version").write_text("3.8.10\n")
            Path(d, "composer.json").write_text("{}\n")
            found = runtimes.runtime_findings(d, fetch=fetch, installed=lambda p: {"php": "8.1.2"}.get(p), today=TODAY)
        text = "\n".join(f"{s} {t}" for s, t in found)
        self.assertIn("HIGH python 3.8.10 (.python-version)", text)
        self.assertIn("INFO language update check for php skipped", text)


if __name__ == "__main__":
    unittest.main()
