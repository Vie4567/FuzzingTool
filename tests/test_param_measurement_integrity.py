"""Parameter name suggestions must not pretend to be HTTP observations."""

from copy import deepcopy
import unittest
from unittest.mock import patch

from src.agents.param_discovery import ParamDiscoveryAgent


class ParameterMeasurementIntegrityTests(unittest.TestCase):
    def test_candidates_have_no_unobserved_http_measurements(self):
        endpoints = [{"path": "/search", "status_code": 200,
                      "content_length": 587, "response_time": 0.013},
                     "/orders/detail"]
        tech_stack = {"backend": "unknown"}
        dev_profile = {"naming_convention": "snake_case", "resources": ["orders"]}
        original = deepcopy((endpoints, tech_stack, dev_profile))

        result = ParamDiscoveryAgent(llm=None)._run_param_discovery_internal(
            target_url="https://example.invalid", endpoints=endpoints,
            tech_stack=tech_stack, dev_profile=dev_profile,
        )

        self.assertEqual((endpoints, tech_stack, dev_profile), original)
        self.assertEqual(result["result_kind"], "parameter_candidates")
        self.assertEqual(result["verification"], "not_checked")
        self.assertFalse(result["verification_performed"])
        self.assertEqual(len(result["param_results"]), 2)
        self.assertGreater(result["assembled_parameter_count"], 0)
        self.assertIn("q", {param["name"] for param in result["param_results"][0]["discovered_params"]})
        for row in result["param_results"]:
            self.assertIsNone(row["status_code"])
            self.assertIsNone(row["content_length_change"])
            self.assertEqual(row["result_kind"], "parameter_candidates")
            self.assertEqual(row["verification"], "not_checked")
            self.assertFalse(row["verification_performed"])
            self.assertTrue(row["discovered_params"])

    def test_execute_reports_plan_separately_from_executed_tools(self):
        agent = ParamDiscoveryAgent(llm=None)
        with patch.object(agent.tool_registry, "execute_tool") as execute_tool:
            result = agent.execute("https://example.invalid", ["/search"])
        execute_tool.assert_not_called()
        self.assertEqual(result["tools_executed"], [])
        self.assertIn("planned_tool", result)
        self.assertEqual(result["planned_tool"]["selected_tool"], "param_discovery_tool")
        self.assertIsNone(result["param_results"][0]["status_code"])
        self.assertIsNone(result["param_results"][0]["content_length_change"])
        self.assertIn("null", result["subagent_justification"])


if __name__ == "__main__":
    unittest.main()
