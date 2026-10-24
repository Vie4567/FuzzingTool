"""Do not turn observed HTTP measurements into invented verification results."""

from copy import deepcopy
import unittest
from unittest.mock import Mock, patch

from src.agents.soft404_filter import Soft404FilterAgent


class Soft404IntegrityTests(unittest.TestCase):
    def test_results_are_deterministic_unverified_and_input_is_unchanged(self):
        records = [
            {"url": "https://example.invalid/a", "status_code": 200,
             "content_length": 137, "response_time": 0.012345,
             "headers": {"Content-Type": "text/html"}},
            {"url": "https://example.invalid/b", "status_code": 403,
             "content_length": 0, "response_time": 0},
            {"url": "https://example.invalid/c", "status_code": 404,
             "content_length": 72, "response_time": 0.001},
            {"url": "https://example.invalid/d", "status_code": 429,
             "content_length": 29, "response_time": 0.004},
            {"url": "https://example.invalid/e", "status_code": None,
             "content_length": None, "response_time": None, "error": "timeout"},
        ]
        original = deepcopy(records)
        agent = Soft404FilterAgent()

        first = agent.execute("https://example.invalid", records)
        second = agent.execute("https://example.invalid", records)

        self.assertEqual(first, second)
        self.assertEqual(records, original)
        self.assertEqual(first["verified"], [])
        self.assertEqual(first["false_positives"], [])
        self.assertIsNone(first["baseline"])
        self.assertFalse(first["verification_performed"])
        self.assertEqual(first["verification_status"], "not_implemented")
        self.assertEqual(len(first["unverified"]), len(records))
        for source, preserved in zip(records, first["unverified"]):
            self.assertIsNot(source, preserved)
            for field in ("status_code", "content_length", "response_time"):
                self.assertEqual(preserved[field], source[field])
                self.assertIs(type(preserved[field]), type(source[field]))
            self.assertEqual(preserved["verification"], "not_checked")
            self.assertFalse(preserved["verification_performed"])
            self.assertNotIn("similarity_to_baseline", preserved)
        first["unverified"][0]["headers"]["Content-Type"] = "changed"
        self.assertEqual(records, original)

    def test_no_llm_or_tool_execution_and_skip_is_logged(self):
        agent = Soft404FilterAgent(llm=Mock())
        with (
            patch.object(agent, "plan_tool_execution") as plan,
            patch.object(agent, "generate_justification") as explain,
            patch.object(agent.tool_registry, "execute_tool") as execute_tool,
            patch("src.agents.soft404_filter.log_agent_skip") as log_skip,
        ):
            result = agent.execute("https://example.invalid", [])
        plan.assert_not_called()
        explain.assert_not_called()
        execute_tool.assert_not_called()
        agent.llm.invoke.assert_not_called()
        log_skip.assert_called_once()
        self.assertEqual(result["tools_executed"], [])
        self.assertEqual(result["unverified"], [])
        self.assertIn("baseline", result["subagent_justification"])

    def test_previous_verification_metadata_is_not_reused(self):
        records = [{"status_code": 200, "content_length": 42,
                    "response_time": 0.03, "verification": "genuine",
                    "verification_performed": True, "similarity_to_baseline": 0.13}]
        original = deepcopy(records)
        result = Soft404FilterAgent().execute("https://example.invalid", records)
        row = result["unverified"][0]
        self.assertEqual(row["verification"], "not_checked")
        self.assertFalse(row["verification_performed"])
        self.assertNotIn("similarity_to_baseline", row)
        self.assertEqual(records, original)


if __name__ == "__main__":
    unittest.main()
