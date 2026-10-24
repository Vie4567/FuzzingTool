"""Local configuration tests; all environment files are temporary fixtures."""

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from dotenv import dotenv_values
from scripts import configure_proxy_profiles as configure


class ProxyConfigurationTests(unittest.TestCase):
    def setUp(self):
        parent = configure.PROJECT_ROOT / "output_samples" / "diagnostics"
        parent.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=parent)
        self.addCleanup(self.temporary.cleanup)
        self.project = Path(self.temporary.name)
        self.env_file = self.project / ".env"

    def _run(self, urls, arguments=None):
        stdout = io.StringIO()
        with patch.object(configure, "PROJECT_ROOT", self.project):
            with patch.object(configure.getpass, "getpass", side_effect=urls):
                with patch("socket.create_connection", side_effect=AssertionError("Configuration cannot use the network")) as connect:
                    with patch.object(configure.ProxyProfilePool, "opener_for", side_effect=AssertionError("Configuration cannot open a transport")) as opener:
                        with redirect_stdout(stdout):
                            code = configure.main(arguments or [])
                connect.assert_not_called()
                opener.assert_not_called()
        return code, stdout.getvalue()

    def test_saved_profiles_preserve_unrelated_secrets_without_printing_them(self):
        original = "# retained comment\nDEEPSEEK_API_KEY=existing-private-key\nOTHER_FLAG=true\nFUZZ_PROXY_PROFILES=\n"
        self.env_file.write_text(original, encoding="utf-8")
        urls = ["http://user:private-proxy-pass@proxy-a.example:3128", "http://proxy-b.example:8080"]
        code, stdout = self._run(urls)
        self.assertEqual(code, 0)
        text = self.env_file.read_text(encoding="utf-8")
        self.assertIn("# retained comment\nDEEPSEEK_API_KEY=existing-private-key\nOTHER_FLAG=true\n", text)
        values = dotenv_values(self.env_file, interpolate=False)
        self.assertEqual(values["DEEPSEEK_API_KEY"], "existing-private-key")
        self.assertEqual(json.loads(values[configure.PROFILE_ENV]), [
            {"id": "egress-a", "url": urls[0]}, {"id": "egress-b", "url": urls[1]},
        ])
        for secret in ("existing-private-key", "private-proxy-pass", *urls):
            self.assertNotIn(secret, stdout)
        self.assertIn("egress-a, egress-b", stdout)
        self.assertIn("No network request was made", stdout)

    def test_quotes_and_dollar_sequences_survive_dotenv_round_trip(self):
        self.env_file.write_text("UNRELATED_API_KEY=do-not-expand\n", encoding="utf-8")
        urls = ["http://user:pa'ss%22${UNRELATED_API_KEY}@proxy-a.example:3128", "http://proxy-b.example:3128"]
        code, stdout = self._run(urls)
        self.assertEqual(code, 0)
        saved = json.loads(dotenv_values(self.env_file, interpolate=False)[configure.PROFILE_ENV])
        self.assertEqual(saved[0]["url"], urls[0])
        self.assertNotIn("do-not-expand", saved[0]["url"])
        self.assertNotIn(urls[0], stdout)

    def test_invalid_or_duplicate_endpoints_leave_existing_file_unchanged(self):
        original = "API_KEY=unchanged\n"
        self.env_file.write_text(original, encoding="utf-8")
        code, stdout = self._run(["http://same.example:3128", "http://same.example:3128"])
        self.assertEqual(code, 2)
        self.assertEqual(self.env_file.read_text(encoding="utf-8"), original)
        self.assertNotIn("same.example", stdout)

    def test_invalid_endpoints_do_not_create_a_file(self):
        code, stdout = self._run(["http://secret@invalid", "http://proxy-b.example:3128"])
        self.assertEqual(code, 2)
        self.assertFalse(self.env_file.exists())
        self.assertNotIn("secret@invalid", stdout)

    def test_terminal_without_hidden_input_stops_before_write(self):
        code, stdout = self._run(configure.getpass.GetPassWarning("no hidden input"))
        self.assertEqual(code, 2)
        self.assertFalse(self.env_file.exists())
        self.assertIn("interactive terminal with hidden input", stdout)

    def test_environment_file_cannot_escape_project(self):
        code, stdout = self._run([], ["--env-file", "../outside.env"])
        self.assertEqual(code, 2)
        self.assertFalse(self.env_file.exists())
        self.assertIn("no changes saved", stdout)


if __name__ == "__main__":
    unittest.main()
