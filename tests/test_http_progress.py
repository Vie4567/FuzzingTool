"""Live progress is emitted around real local requests without routing secrets."""

import base64
import logging
import unittest

import test_proxy_fuzzing as fixtures
from src.tools.http_fuzzing import run_http_fuzzing


class HttpProgressTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.ProxyFuzzingIntegrationTests.setUpClass()

    @classmethod
    def tearDownClass(cls):
        fixtures.ProxyFuzzingIntegrationTests.tearDownClass()

    def setUp(self):
        self.fixture = fixtures.ProxyFuzzingIntegrationTests()
        self.fixture.setUp()

    def test_progress_surrounds_live_requests_and_omits_credentials_and_query(self):
        fixture = self.fixture
        profiles = [dict(profile) for profile in fixture.profiles]
        profiles[0]["url"] = profiles[0]["url"].replace(
            "http://", "http://LiveProxyUser:LiveProxySecret@"
        )
        observations = []

        class Observer(logging.Handler):
            def emit(self, record):
                observations.append((record.getMessage().split()[0], len(fixture.target.state["observed"])))

        logger = logging.getLogger("sentinel.fuzzing.http")
        handler = Observer()
        with self.assertLogs(logger, level="INFO") as captured:
            logger.addHandler(handler)
            try:
                data = run_http_fuzzing(
                    fixture.origin + "?key=PrivateQueryValue", ["one", "two"],
                    engine="proxy_http", allowed_origins=[fixture.origin],
                    proxy_profiles=profiles, rate_limit=10, max_requests=2,
                )
            finally:
                logger.removeHandler(handler)

        self.assertEqual(observations, [("START", 0), ("RESULT", 1), ("START", 1), ("RESULT", 2), ("STOP", 2)])
        result_logs = [message for message in captured.output if "RESULT " in message]
        for message, row in zip(result_logs, data["results"]):
            self.assertIn(f"status={row['status_code']}", message)
            self.assertIn(f"bytes={row['content_length']}", message)
            self.assertIn(f"seconds={row['response_time']:.6f}", message)
        self.assertIn("STOP reason=completed attempted=2 responses=2", captured.output[-1])
        public_log = "\n".join(captured.output)
        for private in ("LiveProxyUser", "LiveProxySecret", "PrivateQueryValue", profiles[0]["url"],
                        base64.b64encode(b"LiveProxyUser:LiveProxySecret").decode()):
            self.assertNotIn(private, public_log)

    def test_429_has_no_start_event_for_next_profile(self):
        self.fixture.target.state["codes"] = [429, 200]
        with self.assertLogs("sentinel.fuzzing.http", level="INFO") as captured:
            data = self.fixture.run_engine(["one", "two"])
        self.assertEqual(len(captured.output), 3)
        self.assertIn("START request=1/2 profile=egress-a", captured.output[0])
        self.assertIn("RESULT request=1 profile=egress-a status=429", captured.output[1])
        self.assertIn("STOP reason=rate_limited_429 attempted=1 responses=1", captured.output[2])
        self.assertEqual(data["stats"]["total_requests"], 1)
        self.assertEqual(self.fixture.proxies[1].state["observed"], [])

    def test_direct_progress_measures_real_responses_and_does_not_follow_redirect(self):
        fixture = self.fixture
        fixture.target.state["redirect_to"] = "http://outside-scope.invalid/landing"
        fixture.target.state["codes"] = [302, 200]
        with self.assertLogs("sentinel.fuzzing.http", level="INFO") as captured:
            data = run_http_fuzzing(
                fixture.origin + "?token=DirectPrivateQuery", ["redirect", "one"],
                engine="python_http", proxy=None, rate_limit=10, max_requests=2,
            )
        self.assertEqual([row["status_code"] for row in data["results"]], [302, 200])
        self.assertEqual(len(fixture.target.state["observed"]), 2)
        self.assertTrue(all(not proxy.state["observed"] for proxy in fixture.proxies))
        messages = [record.getMessage() for record in captured.records]
        self.assertEqual([message.split()[0] for message in messages], ["START", "RESULT", "START", "RESULT", "STOP"])
        self.assertIn("profile=direct", messages[0])
        self.assertIn("status=302", messages[1])
        self.assertIn(f"bytes={len(fixture.target.state['observed'][0]['body'])}", messages[1])
        self.assertIn("STOP reason=completed attempted=2 responses=2", messages[-1])
        self.assertNotIn("DirectPrivateQuery", "\n".join(messages))

    def test_direct_429_stops_before_next_request(self):
        fixture = self.fixture
        fixture.target.state["codes"] = [429, 200]
        with self.assertLogs("sentinel.fuzzing.http", level="INFO") as captured:
            data = run_http_fuzzing(fixture.origin, ["one", "two"], proxy=None, rate_limit=10)
        self.assertEqual(len(fixture.target.state["observed"]), 1)
        self.assertEqual(len(captured.records), 3)
        self.assertEqual(data["stop_reason"], "rate_limited_429")


if __name__ == "__main__":
    unittest.main()
