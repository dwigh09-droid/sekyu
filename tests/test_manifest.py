import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load(rel):
    return json.loads((ROOT / rel).read_text(encoding="utf-8"))


class ManifestTests(unittest.TestCase):
    def test_json_parses(self):
        for rel in (".claude-plugin/plugin.json", ".claude-plugin/marketplace.json", "hooks/hooks.json"):
            with self.subTest(rel=rel):
                load(rel)

    def test_plugin_name(self):
        self.assertEqual(load(".claude-plugin/plugin.json")["name"], "sekyu")

    def test_hook_scripts_exist(self):
        hooks = load("hooks/hooks.json")["hooks"]
        commands = [h["command"] for entries in hooks.values() for e in entries for h in e["hooks"]]
        self.assertTrue(commands)
        for cmd in commands:
            for script in re.findall(r"/hooks/(\w+\.py)", cmd):
                self.assertTrue((ROOT / "hooks" / script).is_file(), script)

    def test_warns_when_python_missing(self):
        start = load("hooks/hooks.json")["hooks"]["SessionStart"][0]["hooks"][0]["command"]
        self.assertIn("python", start)
        self.assertIn("sekyu", start)

    def test_hooks_have_timeouts(self):
        hooks = load("hooks/hooks.json")["hooks"]
        for h in (h for entries in hooks.values() for e in entries for h in e["hooks"]):
            self.assertIn("timeout", h)

    def test_audit_command(self):
        text = (ROOT / "commands/sekyu-audit.md").read_text(encoding="utf-8")
        self.assertRegex(text, r"(?m)^description: .+")
        self.assertIn("hooks/audit.py", text)
        self.assertTrue((ROOT / "hooks/audit.py").is_file())

    def test_ci_workflow(self):
        self.assertTrue((ROOT / ".github/dependabot.yml").is_file())
        text = (ROOT / ".github/workflows/security.yml").read_text(encoding="utf-8")
        for word in ("unittest", "gitleaks", "semgrep", "contents: read"):
            self.assertIn(word, text)

    def test_skill_recommends_security_review(self):
        self.assertIn("/security-review", (ROOT / "skills/secure-coding/SKILL.md").read_text(encoding="utf-8"))

    def test_rce_hunter_agent(self):
        text = (ROOT / "agents/rce-hunter.md").read_text(encoding="utf-8")
        self.assertTrue(text.startswith("---"))
        self.assertIn("name: rce-hunter", text)
        self.assertRegex(text, r"(?m)^description: .+")
        lower = text.lower()
        for must in ("deserializ", "subprocess", "template", "planted", "path traversal", "eval",
                     "proven", "suspected", "harmless marker", "never run the repo's own"):
            self.assertIn(must, lower)

    def test_rce_command_uses_agent(self):
        text = (ROOT / "commands/sekyu-rce.md").read_text(encoding="utf-8")
        self.assertRegex(text, r"(?m)^description: .+")
        self.assertIn("sekyu:rce-hunter", text)

    def test_skill_frontmatter(self):
        text = (ROOT / "skills/secure-coding/SKILL.md").read_text(encoding="utf-8")
        self.assertTrue(text.startswith("---"))
        self.assertIn("name: secure-coding", text)
        self.assertRegex(text, r"(?m)^description: .+")
        self.assertLessEqual(len(text.split("---", 2)[2].strip().splitlines()), 40)


if __name__ == "__main__":
    unittest.main()
