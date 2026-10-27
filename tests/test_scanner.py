import json
import tempfile
import unittest
from pathlib import Path

from repo_doctor import markdown, sarif, scan


class ScannerTest(unittest.TestCase):
    def test_detects_real_key_without_printing_value(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            model_key = "sk-" + "project-9u3Q7m2V8x4K6p1N5r0T7y3W9q2L8s4"
            github_token = "ghp_" + "8K4mQ2vN7xP5rT9sL3wY6cB1dF0hJ7"
            (root / ".env").write_text(f"OPENAI_API_KEY={model_key}\n", encoding="utf-8")
            (root / "app.py").write_text(f"token = '{github_token}'\n", encoding="utf-8")
            report = scan(root)
            self.assertGreaterEqual(report["summary"]["high"], 1)
            self.assertTrue(any(item["rule"] == "sensitive-file" for item in report["findings"]))
            rendered = json.dumps(report)
            self.assertNotIn(model_key, rendered)

    def test_ignores_documented_placeholders_and_writes_formats(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".gitignore").write_text(".env\nnode_modules/\n", encoding="utf-8")
            (root / "README.md").write_text("JWT_SECRET=<random-secret-of-at-least-32-bytes>\n", encoding="utf-8")
            report = scan(root)
            self.assertEqual(report["summary"]["total"], 0)
            self.assertIn("No configured", markdown(report))
            self.assertEqual(sarif(report)["version"], "2.1.0")


if __name__ == "__main__":
    unittest.main()
