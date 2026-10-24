"""Wordlist generation preserves per-slot LLM evidence through its real pipeline."""

import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import unittest
from unittest.mock import patch

from langchain_core.messages import AIMessage
from langchain_core.runnables import RunnableLambda
from src.agents.wordlist_gen import WordlistGenAgent


class WordlistPatternTraceTests(unittest.TestCase):
    def test_real_wordlist_flow_logs_parts_and_writes_assembly_trace(self):
        root = Path(__file__).resolve().parents[1]
        profile = {
            "naming_convention": "kebab-case", "versioning": "none", "crud_pattern": "RESTful",
            "business_domain": "offline catalog fixture",
            "url_hierarchy": {"style": "flat-feature-routes", "common_prefix": "", "detected_services": []},
        }

        def reply(value):
            messages = value if isinstance(value, list) else value.to_messages()
            text = "\n".join(message.content for message in messages)
            part = re.search(r"ONLY the '([^']+)' slot", text)
            if "YEU CAU PHAN TICH 8 CHIEU" in text:
                content = json.dumps(profile)
            elif part:
                content = json.dumps(["llm-" + part.group(1).replace("_", "-")])
            elif '"selected_tool"' in text:
                content = json.dumps({"selected_tool": "wordlist_generator_tool", "options": {},
                                      "tool_selection_reason": "offline fixture", "is_task_complete": True})
            elif "Sub-Agent Justification Report" in text:
                content = "Offline candidate generation; no HTTP verification."
            else:
                content = '["catalog-entry"]'
            return AIMessage(content=content, response_metadata={"model_name": "offline-fixture"})

        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            shutil.copytree(root / "knowledge", out / "knowledge")
            original_cwd = Path.cwd()
            try:
                os.chdir(out)
                with patch.dict(os.environ, {"LLM_RESPONSE_LOG_FILE": str(out / "responses.jsonl")}):
                    with patch("socket.create_connection", side_effect=AssertionError("No network in this fixture")):
                        result = WordlistGenAgent(llm=RunnableLambda(reply)).execute(
                            tech_stack={"target_url": "https://catalog.example.invalid", "backend": "unknown"},
                            discovered_paths=["/wallet", "/manifest.json", "/wallet"],
                        )
            finally:
                os.chdir(original_cwd)

            trace = json.loads((out / "output_samples/02_pattern_trace.json").read_text(encoding="utf-8"))
            rows = [json.loads(line) for line in (out / "responses.jsonl").read_text(encoding="utf-8").splitlines()]
            parts = [row for row in rows if row["component"] == "EndpointAssembler"]
            self.assertTrue(parts)
            self.assertTrue(all(row["status"] == "ok" for row in rows))
            self.assertEqual(result["generation_strategy"], "component_by_component_then_template_assembly")
            self.assertEqual(trace["endpoint_assembly"], result["assembler_metadata"])
            self.assertEqual(result["metadata"]["recon_paths_included"], 2)
            self.assertIn("/manifest.json", result["wordlist"])
            self.assertNotIn("manifest.json", trace["endpoint_assembly"]["part_vocabularies"]["resource"])
            self.assertTrue(any("llm-resource" in path for path in result["wordlist"]))
            self.assertTrue(trace["endpoint_assembly"]["pattern_results"])
            for row in parts:
                part = row["context"]["part"]
                self.assertIn("llm-" + part.replace("_", "-"), trace["endpoint_assembly"]["llm_part_items"][part])
                self.assertTrue(row["context"]["pattern_ids"])
            self.assertIn("sensitive_file_groups", trace)
            self.assertIn("parameter_groups", trace)
            self.assertTrue((out / "output_samples/02_wordlist_result.json").exists())
            self.assertEqual(result["metadata"]["llm_response_log_file"], str(out / "responses.jsonl"))


if __name__ == "__main__":
    unittest.main()
