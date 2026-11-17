"""Ground-truth signature fixtures: no sockets, model calls or optional parser."""

from copy import deepcopy
from email.message import Message
import json
from pathlib import Path
import unittest

from src.tools.tech_fingerprints import header_fingerprint, resolve_technologies


_KNOWLEDGE = Path(__file__).resolve().parents[1] / "knowledge"
_FP = json.loads((_KNOWLEDGE / "tech_fingerprints.json").read_text(encoding="utf-8"))
_WAF = json.loads((_KNOWLEDGE / "waf_signatures.json").read_text(encoding="utf-8"))


class ReconFingerprintTests(unittest.TestCase):
    def headers(self, headers=None, body=""):
        return header_fingerprint(headers or {}, body, _FP, _WAF)

    def resolve(self, headers=None, body="", hints=None, meta=None):
        ch1 = self.headers(headers, body)
        return resolve_technologies(ch1["tech_stack"], hints, meta,
                                    evidence=ch1["technology_evidence"], body=body, fp_data=_FP)

    def test_plain_server_header_is_not_ddos_guard_or_a_waf(self):
        for value in ("nginx/1.25", "Apache", "Python/3.12", "gunicorn", "unknown_server"):
            with self.subTest(server=value):
                result = self.headers({"Server": value})
                self.assertFalse(result["waf_detected"])
                self.assertIsNone(result["waf_type"])
                self.assertEqual(result["waf_evidence"], [])
                self.assertEqual(result["tech_stack"]["web_server"], value)

    def test_header_names_are_not_searched_inside_unrelated_values(self):
        result = self.headers({"X-Example": "x-modsecurity-id x-sucuri-id cf-ray server"})
        self.assertFalse(result["waf_detected"])
        self.assertEqual(result["waf_candidates"], [])

    def test_generic_cache_and_denial_messages_do_not_identify_waf(self):
        result = self.headers({"X-Cache": "HIT", "X-CDN": "unspecified"},
                              "Access Denied. Request blocked. Not Acceptable. Reference #123.")
        self.assertFalse(result["waf_detected"])
        self.assertEqual(result["waf_candidates"], [])

    def test_cdn_identity_alone_remains_candidate(self):
        cases = (
            ({"Server": "cloudflare", "CF-Ray": "fixture-ray"}, "cloudflare"),
            ({"Server": "CloudFront", "X-Amz-Cf-Id": "fixture-id"}, "aws_waf"),
            ({"Server": "AkamaiGHost"}, "akamai"),
            ({"X-Azure-Ref": "fixture-ref"}, "azure_fd"),
        )
        for headers, vendor in cases:
            with self.subTest(vendor=vendor):
                result = self.headers(headers)
                self.assertFalse(result["waf_detected"])
                self.assertIsNone(result["waf_type"])
                self.assertTrue(any(item["value"] == vendor for item in result["waf_candidates"]))
                self.assertTrue(all(item["classification"] == "candidate" for item in result["waf_candidates"]))

    def test_specific_waf_header_retains_signature_without_private_value(self):
        result = self.headers({"X-ModSecurity-Id": "fixture_private_request_identifier"})
        self.assertTrue(result["waf_detected"])
        self.assertEqual(result["waf_type"], "modsecurity")
        self.assertEqual(result["waf_evidence"][0]["indicator"], "x-modsecurity-id")
        self.assertNotIn("fixture_private_request_identifier", json.dumps(result))

    def test_body_only_specific_signatures_are_supported(self):
        for text, vendor in (("Attention Required! | Cloudflare", "cloudflare"),
                             ("Blocked by ModSecurity", "modsecurity"),
                             ("Azure Web Application Firewall", "azure_fd"),
                             ("DDoS-Guard", "ddos_guard")):
            with self.subTest(vendor=vendor):
                result = self.headers(body=text)
                self.assertEqual(result["waf_type"], vendor)
                self.assertTrue(result["waf_detected"])
                self.assertEqual(result["waf_evidence"][0]["source"], "body_signature")

    def test_specific_server_product_differs_from_generic_server_header(self):
        result = self.headers({"Server": "DDoS-Guard"})
        self.assertEqual(result["waf_type"], "ddos_guard")
        self.assertEqual(result["waf_evidence"][0]["indicator"], "server:DDoS-Guard")

    def test_cookie_names_are_matched_not_cookie_values_or_partial_names(self):
        for cookie in ("session=cf_clearance", "not_cf_clearance=fixture", "session=laravel_session",
                       "not_PHPSESSID=fixture", "note=JSESSIONID"):
            with self.subTest(cookie=cookie):
                result = self.headers({"Set-Cookie": cookie})
                self.assertFalse(result["waf_detected"])
                self.assertEqual(result["tech_stack"]["language"], "Unknown")
                self.assertEqual(result["tech_stack"]["backend"], "Unknown")

    def test_cookie_evidence_preserves_names_without_cookie_values(self):
        result = self.headers({"Set-Cookie": ["cf_clearance=fixture_private_cookie; Path=/",
                                               "laravel_session=fixture_private_session; HttpOnly"]})
        self.assertEqual(result["waf_type"], "cloudflare")
        self.assertEqual(result["tech_stack"]["backend"], "laravel")
        self.assertNotIn("fixture_private_cookie", json.dumps(result))
        self.assertNotIn("fixture_private_session", json.dumps(result))

    def test_repeated_set_cookie_headers_are_preserved_when_available(self):
        headers = Message()
        headers.add_header("Set-Cookie", "unrelated=first")
        headers.add_header("Set-Cookie", "laravel_session=second")
        result = header_fingerprint(headers, "", _FP, _WAF)
        self.assertEqual(result["tech_stack"]["backend"], "laravel")
        matches = [e for e in result["technology_evidence"] if e["field"] == "backend"]
        self.assertEqual(len(matches), 1)

    def test_multiple_waf_signatures_do_not_select_first_vendor(self):
        result = self.headers({"X-ModSecurity-Id": "fixture", "X-Sucuri-Id": "fixture"})
        self.assertTrue(result["waf_detected"])
        self.assertIsNone(result["waf_type"])
        self.assertEqual(result["waf_status"], "conflicting")
        self.assertEqual({e["value"] for e in result["waf_evidence"]}, {"modsecurity", "sucuri"})

    def test_no_signatures_keeps_all_layers_unknown(self):
        result = self.resolve(body="<html><p>Plain static page</p></html>")
        for field in ("frontend", "backend", "cms", "language"):
            self.assertEqual(result[field], "Unknown")
        self.assertEqual(result["technology_evidence"], [])

    def test_react_frontend_preserves_aspnet_backend_without_guessing_csharp(self):
        result = self.resolve({"X-Powered-By": "ASP.NET"}, '<div data-reactroot=""></div>')
        self.assertEqual(result["frontend"], "React")
        self.assertEqual(result["backend"], "asp_net")
        self.assertEqual(result["cms"], "Unknown")
        self.assertEqual(result["language"], "Unknown")
        self.assertTrue(any(e["source"] == "dom_attribute" and e["value"] == "React"
                            for e in result["technology_evidence"]))

    def test_frontend_alone_does_not_establish_backend_or_backend_language(self):
        for body, frontend in (('<div data-reactroot></div>', "React"),
                               ('<div data-v-fixture></div>', "Vue.js"),
                               ('<div ng-version="17"></div>', "Angular"),
                               ('<div id="__next"></div>', "Next.js"),
                               ('<div id="__nuxt"></div>', "Nuxt.js")):
            with self.subTest(frontend=frontend):
                result = self.resolve(body=body)
                self.assertEqual(result["frontend"], frontend)
                for field in ("backend", "language", "cms"):
                    self.assertEqual(result[field], "Unknown")

    def test_header_language_remains_independent_of_frontend(self):
        result = self.resolve({"X-Powered-By": "PHP/8.3"}, '<div data-reactroot></div>')
        self.assertEqual(result["frontend"], "React")
        self.assertEqual(result["language"], "PHP")
        self.assertEqual(result["backend"], "Unknown")

    def test_wordpress_meta_classifies_cms_and_marks_language_inferred(self):
        result = self.resolve(body='<meta content="WordPress 6.0" name="generator">')
        self.assertEqual(result["cms"], "WordPress")
        self.assertEqual(result["language"], "PHP")
        self.assertEqual(result["backend"], "Unknown")
        self.assertEqual(result["frontend"], "Unknown")
        self.assertTrue(any(e["field"] == "cms" and e["source"] == "meta_generator"
                            and e["classification"] == "observed" for e in result["technology_evidence"]))
        self.assertTrue(any(e["field"] == "language" and e["classification"] == "inferred"
                            for e in result["technology_evidence"]))

    def test_header_and_cookie_frameworks_resolve_to_separate_layers(self):
        cases = (({"X-Generator": "Drupal"}, "Unknown", "Drupal", "PHP"),
                 ({"X-Powered-By": "Express"}, "express", "Unknown", "JavaScript"),
                 ({"Set-Cookie": "laravel_session=fixture"}, "laravel", "Unknown", "PHP"),
                 ({"Set-Cookie": "_rails_session=fixture"}, "rails", "Unknown", "Ruby"))
        for headers, backend, cms, language in cases:
            with self.subTest(headers=list(headers)):
                result = self.resolve(headers)
                self.assertEqual((result["backend"], result["cms"], result["language"]),
                                 (backend, cms, language))

    def test_java_session_does_not_prove_spring_and_csrf_cookie_does_not_prove_django(self):
        servlet = self.resolve({"Set-Cookie": "JSESSIONID=fixture"})
        self.assertEqual(servlet["backend"], "Unknown")
        self.assertEqual(servlet["language"], "Java")
        csrf = self.resolve({"Set-Cookie": "csrftoken=fixture"})
        self.assertEqual(csrf["backend"], "Unknown")
        self.assertEqual(csrf["language"], "Unknown")
        self.assertTrue(all(e["classification"] == "candidate" for e in csrf["technology_evidence"]))

    def test_unattributed_hints_generic_admin_and_prose_do_not_prove_framework(self):
        result = self.resolve(body='<a href="/admin/">Guide to django data-reactroot ng-app</a>',
                              hints=["django", "react", "django_or_generic"])
        for field in ("frontend", "backend", "cms", "language"):
            self.assertEqual(result[field], "Unknown")
        self.assertTrue(all(e["classification"] == "candidate" for e in result["technology_evidence"]))

    def test_backend_conflicts_leave_unknown_and_preserve_both_evidence_sources(self):
        result = self.resolve({"X-Powered-By": "Express", "Set-Cookie": "laravel_session=fixture"})
        self.assertEqual(result["backend"], "Unknown")
        self.assertEqual(result["language"], "Unknown")
        self.assertEqual({e["value"] for e in result["technology_evidence"] if e["field"] == "backend"},
                         {"express", "laravel"})
        self.assertEqual({c["field"] for c in result["technology_conflicts"]}, {"backend", "language"})

    def test_cms_conflicts_are_not_silently_overwritten_by_meta_generator(self):
        result = self.resolve({"X-Generator": "Drupal"}, '<meta name="generator" content="WordPress">')
        self.assertEqual(result["cms"], "Unknown")
        self.assertEqual(result["language"], "PHP")
        self.assertEqual(result["technology_conflicts"][0]["values"], ["Drupal", "WordPress"])

    def test_malformed_meta_attributes_do_not_abort_resolution(self):
        result = self.resolve(body='<meta name><meta name="generator"><div data-reactroot></div>')
        self.assertEqual(result["frontend"], "React")
        self.assertEqual(result["cms"], "Unknown")

    def test_malformed_declaration_keeps_header_and_prior_dom_evidence(self):
        result = self.resolve({"X-Powered-By": "PHP/8.3"},
                              '<div data-reactroot></div><![unsupported_fixture_private_content]>')
        self.assertEqual(result["frontend"], "React")
        self.assertEqual(result["language"], "PHP")
        self.assertEqual(result["technology_errors"], [{
            "error_type": "html_parse_error", "message": "HTML fingerprint parsing did not complete"}])
        self.assertNotIn("unsupported_fixture_private_content", json.dumps(result))

    def test_matching_is_case_insensitive_without_unrelated_substring_matches(self):
        result = self.resolve({"x-powered-by": "pHp/8.3", "x-generator": "wOrDpReSs"})
        self.assertEqual(result["language"], "PHP")
        self.assertEqual(result["cms"], "WordPress")
        self.assertEqual(self.resolve({"X-Powered-By": "NotExpress"})["backend"], "Unknown")

    def test_findings_are_json_serializable_and_inputs_not_modified(self):
        headers = {"Server": "nginx", "Authorization": "Bearer fixture_should_not_appear",
                   "Set-Cookie": ["PHPSESSID=fixture_cookie_should_not_appear"]}
        before = deepcopy((headers, _FP, _WAF))
        ch1 = self.headers(headers)
        resolved = self.resolve(headers, '<div data-reactroot></div>')
        self.assertEqual((headers, _FP, _WAF), before)
        serialized = json.dumps({"ch1": ch1, "resolved": resolved})
        self.assertNotIn("fixture_should_not_appear", serialized)
        self.assertNotIn("fixture_cookie_should_not_appear", serialized)
        for item in resolved["technology_evidence"]:
            self.assertEqual(set(item), {"field", "value", "source", "indicator", "classification"})
            self.assertIn(item["classification"], {"observed", "candidate", "inferred"})


if __name__ == "__main__":
    unittest.main()
