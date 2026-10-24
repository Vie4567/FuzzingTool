"""Offline checks for component generation, template assembly and provenance."""

import json
import os
from pathlib import Path
import re
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from src.agents.endpoint_assembler import EndpointAssembler


class ComponentLLM:
    def __init__(self, responses):
        self.responses = responses
        self.parts = []

    def invoke(self, messages):
        prompt = messages[-1].content
        part = re.search(r"ONLY the '([^']+)' slot", prompt).group(1)
        self.parts.append(part)
        value = self.responses.get(part, ["contextual-" + part.replace("_", "-")])
        return SimpleNamespace(content=value if isinstance(value, str) else json.dumps(value))


class EndpointPatternGenerationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.response_log = Path(self.directory.name) / "responses.jsonl"
        self.env = patch.dict(os.environ, {"LLM_RESPONSE_LOG_FILE": str(self.response_log)})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.assembler = EndpointAssembler()
        self.profile = {
            "common_prefix": "/api", "api_versioning": "none", "naming_convention": "kebab-case",
            "llm_analysis": {"business_domain": "local test catalog", "crud_pattern": "RESTful"},
        }

    def test_separate_selected_parts_are_logged_then_assembled(self):
        llm = ComponentLLM({"service": ["catalog-service"], "resource": ["catalog-items"], "action": ["inspect"]})
        result = self.assembler.assemble(
            self.profile, selected_pattern_ids=["rest_microservice_nested"], llm=llm, max_endpoints=200,
        )
        self.assertEqual(llm.parts, ["service", "resource", "action"])
        self.assertIn("/api/catalog-service/catalog-items/inspect", result["endpoints"])
        meta = result["metadata"]
        self.assertEqual(meta["llm_part_items"]["resource"], ["catalog-items"])
        self.assertIn({"value": "catalog-items", "sources": ["llm"]}, meta["slot_sources"]["resource"])
        self.assertEqual(meta["selected_patterns"][0]["template"], "{prefix}/{service}/{resource}/{action}")
        self.assertIn("catalog-items", meta["pattern_results"][0]["used_values"]["resource"])
        rows = [json.loads(line) for line in self.response_log.read_text(encoding="utf-8").splitlines()]
        self.assertEqual([row["context"]["part"] for row in rows], llm.parts)
        self.assertTrue(all(row["operation"] == "generate_part" for row in rows))
        self.assertIn("catalog-service", rows[0]["response"]["content"])

    def test_only_parts_required_by_selected_patterns_are_requested(self):
        llm = ComponentLLM({"resource": ["catalog-items"]})
        self.assembler.assemble(self.profile, selected_pattern_ids=["rest_resource_crud"], llm=llm)
        self.assertEqual(llm.parts, ["resource"])

    def test_all_semantic_slots_are_enriched_when_selected(self):
        llm = ComponentLLM({})
        result = self.assembler.assemble(
            self.profile, selected_pattern_ids=["auth_endpoints", "internal_debug", "export_import", "webhook_callback"],
            llm=llm, max_endpoints=400,
        )
        self.assertEqual(set(llm.parts), {"service", "resource", "action", "auth_segment", "internal_segment", "batch_action", "event"})
        self.assertNotIn("prefix", llm.parts)
        self.assertNotIn("id_param", llm.parts)
        for part in ("auth_segment", "internal_segment", "batch_action", "event"):
            self.assertIn("contextual-" + part.replace("_", "-"), result["metadata"]["part_vocabularies"][part])

    def test_invalid_component_values_never_enter_templates(self):
        invalid = ["/api/users", "https://example.test/a", "users/list", "detail-manifest.json", "users?debug=1", "users#x", "../admin", "bad value", "", 123, {"name": "users"}]
        llm = ComponentLLM({"resource": invalid + ["catalog-items", "catalog-items"]})
        result = self.assembler.assemble(self.profile, selected_pattern_ids=["rest_resource_crud"], llm=llm)
        self.assertEqual(result["metadata"]["llm_part_items"]["resource"], ["catalog-items"])
        self.assertIn("/api/catalog-items", result["endpoints"])
        self.assertTrue(all(not any(mark in path for mark in (".json", "?", "#", "://", "..")) for path in result["endpoints"]))

    def test_malformed_response_is_logged_and_falls_back(self):
        llm = ComponentLLM({"resource": '{"not": "an array"}'})
        result = self.assembler.assemble(self.profile, selected_pattern_ids=["rest_resource_crud"], llm=llm)
        self.assertFalse(result["metadata"]["llm_enriched"])
        self.assertEqual(result["metadata"]["llm_part_items"]["resource"], [])
        self.assertIn("/api/users", result["endpoints"])
        row = json.loads(self.response_log.read_text(encoding="utf-8").splitlines()[0])
        self.assertEqual(row["response"]["content"], '{"not": "an array"}')

    def test_static_files_are_not_semantic_resources(self):
        observed = ["/manifest.json", "/api/oembed.json", "/src/assets/styles/global/global.scss", "/static/app.js", "/wallet", "/api/users/list"]
        result = self.assembler.assemble(self.profile, observed_urls=observed, selected_pattern_ids=["rest_versioned_resource"])
        extracted = result["metadata"]["url_analysis"]["extracted_parts"]
        self.assertEqual(set(extracted["resource"]), {"wallet", "users"})
        self.assertNotIn("src", extracted["resource"])
        self.assertTrue(all("manifest.json" not in path and "oembed.json" not in path and "global.scss" not in path for path in result["endpoints"]))

    def test_flat_profile_has_bare_prefix_and_no_invented_microservice(self):
        flat = {"common_prefix": None, "api_versioning": "none", "detected_services": [], "llm_analysis": {"crud_pattern": "action-based", "url_hierarchy": {"style": "flat-feature-routes", "common_prefix": None}, "versioning": "none"}}
        result = self.assembler.assemble(flat, observed_urls=["/wallet", "/account", "/api/oembed.json"])
        meta = result["metadata"]
        self.assertEqual(meta["part_vocabularies"]["prefix"], [""])
        self.assertTrue(all("service" not in pattern["parts"] for pattern in meta["selected_patterns"]))
        self.assertIn("/wallet", result["endpoints"])
        self.assertTrue(all("/none" not in path and "/v1" not in path for path in result["endpoints"]))

    def test_absent_version_prefix_is_deterministic(self):
        first = self.assembler._generate_parts({})["prefix"]
        self.assertEqual(first, [""])
        for _ in range(5):
            self.assertEqual(first, self.assembler._generate_parts({})["prefix"])

    def test_dynamic_ids_stay_separate_from_semantic_slots(self):
        parts = self.assembler._generate_parts(self.profile, url_analysis={"extracted_parts": {
            "id_param": ["{order_id}", "123", "{../admin}", "{id}/../admin"],
            "resource": ["users", "{order_id}", "123"],
        }})
        self.assertIn("{order_id}", parts["id_param"])
        self.assertNotIn("{../admin}", parts["id_param"])
        self.assertNotIn("{id}/../admin", parts["id_param"])
        self.assertNotIn("{order_id}", parts["resource"])
        self.assertNotIn("123", parts["resource"])

    def test_pattern_scoring_does_not_infer_ids_or_services_from_static_shape(self):
        analysis = self.assembler.analyze_observed_urls(["/wallet", "/api/users", "/src/assets/styles/global.scss"])
        self.assertNotIn("rest_microservice_id_action", analysis["pattern_scores"])
        self.assertNotIn("rest_microservice_nested", analysis["pattern_scores"])
        self.assertIn("rest_resource_crud", analysis["pattern_scores"])

    def test_budget_uses_enriched_values_after_long_observed_vocabulary(self):
        observed = ["/api/resource-" + str(index) for index in range(20)]
        llm = ComponentLLM({"resource": ["contextual-resource"], "action": ["inspect"]})
        result = self.assembler.assemble(self.profile, observed_urls=observed, selected_pattern_ids=["rest_versioned_resource"], llm=llm, max_endpoints=100)
        self.assertIn("contextual-resource", result["metadata"]["pattern_results"][0]["used_values"]["resource"])
        self.assertTrue(any("/contextual-resource/" in path for path in result["endpoints"]))


if __name__ == "__main__":
    unittest.main()
