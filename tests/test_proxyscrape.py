"""Provider parsing and pool lifecycle checks; no public network is contacted."""

import json
import ssl
import unittest
from unittest.mock import MagicMock, patch
from urllib.error import URLError
from urllib.request import HTTPSHandler, ProxyHandler

from src.tools import proxyscrape
from src.tools.proxy_profiles import ProxyProfilePool


class ProxyScrapeProviderTests(unittest.TestCase):
    def test_normalizes_deduplicates_and_rejects_non_public_or_non_http(self):
        source = "\n".join([
            "# provider comment", "1.1.1.1:80", "http://1.1.1.1:80",
            "HTTP://8.8.8.8:3128", "[2606:4700:4700::1111]:8080",
            "http://[2606:4700:4700:0:0:0:0:1111]:8080",
            "127.0.0.1:80", "10.0.0.1:80", "169.254.169.254:80",
            "100.64.0.1:80", "0.0.0.0:80", "224.0.0.1:80", "240.0.0.1:80",
            "192.0.2.1:80", "[::1]:80", "[fe80::1]:80", "[ff02::1]:80",
            "[::ffff:127.0.0.1]:80", "http://[fe80::1%eth0]:80",
            "proxy.example:80", "socks5://8.8.8.8:80", "https://8.8.8.8:80",
            "http://user:secret@8.8.8.8:80", "8.8.8.8:0", "8.8.8.8:65536",
            "8.8.8.8", "8.8.8.8:80/", "8.8.8.8:80?", "8.8.8.8:80#",
            "8.8.8.8:80\\evil", "8.8.8.8:\t80", "bad format",
        ])
        self.assertEqual(proxyscrape.parse_http_proxy_urls(source), [
            "http://1.1.1.1:80", "http://8.8.8.8:3128",
            "http://[2606:4700:4700::1111]:8080",
        ])

    def test_limit_counts_unique_valid_candidates(self):
        source = "10.0.0.1:80\n1.1.1.1:80\n1.1.1.1:80\n8.8.8.8:80\n9.9.9.9:80"
        self.assertEqual(proxyscrape.parse_http_proxy_urls(source, limit=2), [
            "http://1.1.1.1:80", "http://8.8.8.8:80",
        ])

    def response(self, body, **overrides):
        response = MagicMock()
        response.__enter__.return_value = response
        response.geturl.return_value = overrides.get("url", proxyscrape.SOURCE_URL)
        response.status = overrides.get("status", 200)
        response.read.return_value = body
        return response

    def test_fetch_fixed_api_bounded_body_no_ambient_proxy_redirect_or_credentials(self):
        response = self.response(b"\xef\xbb\xbf1.1.1.1:80\n8.8.8.8:80\n9.9.9.9:80")
        with patch.object(proxyscrape, "build_opener") as builder:
            builder.return_value.open.return_value = response
            result = proxyscrape.fetch_candidates(timeout=1.5, limit=2)
        self.assertEqual(len(result), 2)
        request = builder.return_value.open.call_args.args[0]
        self.assertEqual(request.full_url, proxyscrape.SOURCE_URL)
        self.assertNotIn("Authorization", dict(request.header_items()))
        self.assertEqual(builder.return_value.open.call_args.kwargs, {"timeout": 1.5})
        response.read.assert_called_once_with(proxyscrape.MAX_BYTES + 1)
        handlers = builder.call_args.args
        proxy = next(handler for handler in handlers if isinstance(handler, ProxyHandler))
        self.assertEqual(proxy.proxies, {})
        no_redirect = next(handler for handler in handlers if isinstance(handler, proxyscrape._NoRedirect))
        self.assertIsNone(no_redirect.redirect_request(request, None, 302, "redirect", {}, "http://127.0.0.1"))

    def test_fetch_keeps_default_verified_tls(self):
        captured = []
        real_builder = proxyscrape.build_opener

        def build(*handlers):
            opener = real_builder(*handlers)
            captured.extend(opener.handlers)
            opener.open = MagicMock(return_value=self.response(b"1.1.1.1:80"))
            return opener

        with patch.object(proxyscrape, "build_opener", side_effect=build):
            proxyscrape.fetch_candidates()
        https = next(handler for handler in captured if isinstance(handler, HTTPSHandler))
        self.assertEqual(https._context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(https._context.check_hostname)

    def test_fetch_rejects_large_or_unexpected_response(self):
        cases = [
            self.response(b"a" * (proxyscrape.MAX_BYTES + 1)),
            self.response(b"1.1.1.1:80", url="https://elsewhere.invalid/"),
            self.response(b"1.1.1.1:80", status=302),
        ]
        for response in cases:
            with self.subTest(status=response.status), patch.object(proxyscrape, "build_opener") as builder:
                builder.return_value.open.return_value = response
                with self.assertRaises(ValueError):
                    proxyscrape.fetch_candidates()

    def test_invalid_fetch_options_fail_before_network(self):
        with patch.object(proxyscrape, "build_opener") as builder:
            for options in ({"timeout": 0}, {"timeout": float("nan")}, {"timeout": True},
                            {"limit": 0}, {"limit": 101}, {"limit": 1.5}, {"limit": True}):
                with self.subTest(options=options), self.assertRaises(ValueError):
                    proxyscrape.fetch_candidates(**options)
            builder.assert_not_called()


class ManagedProxyPoolTests(unittest.TestCase):
    target = "https://authorized.example"
    urls = ["http://1.1.1.1:80", "http://8.8.8.8:8080", "http://9.9.9.9:80"]

    def auto(self, **options):
        return ProxyProfilePool.from_options({
            "engine": "proxy_http", "allowed_origins": [self.target],
            "proxy_source": "proxyscrape", **options,
        }, self.target)

    def refresh(self, pool, urls=None, now=10):
        with patch("src.tools.proxy_profiles.proxyscrape.fetch_candidates", return_value=self.urls if urls is None else urls) as fetch:
            result = pool.refresh(timeout=2, now=now)
        return result, fetch

    def test_configuration_is_network_free_and_auto_starts_empty(self):
        with patch("src.tools.proxy_profiles.proxyscrape.fetch_candidates", side_effect=AssertionError("No I/O")):
            pool = self.auto()
        self.assertTrue(pool.managed)
        self.assertEqual(pool.count_limit, 2)
        self.assertEqual(pool.healthcheck_url, self.target + "/robots.txt")
        self.assertEqual(pool.profile_ids, [])
        self.assertIsNone(pool.next_opener())
        self.assertIsNone(pool.next_pending())
        self.assertTrue(pool.refresh_due(10))

    def test_only_health_checked_profiles_rotate_and_count_is_bounded(self):
        pool = self.auto(proxy_count=2, proxy_candidate_limit=3)
        event, fetch = self.refresh(pool)
        fetch.assert_called_once_with(timeout=2, limit=3)
        self.assertEqual(event["pending_count"], 3)
        self.assertIsNone(pool.next_opener())
        first = pool.next_pending()[0]
        second = pool.next_pending()[0]
        self.assertNotEqual(first, second)
        pool.mark_checked(first, True)
        pool.mark_checked(second, True)
        self.assertIsNone(pool.next_pending())
        self.assertEqual([pool.next_opener()[0] for _ in range(5)], [first, second, first, second, first])
        self.assertIs(pool.opener_by_id(first), pool.opener_for(0)[1])

    def test_refresh_retains_healthy_identity_and_does_not_resurrect_excluded(self):
        pool = self.auto()
        self.refresh(pool)
        first, second = pool.next_pending()[0], pool.next_pending()[0]
        pool.mark_checked(first, True)
        pool.mark_checked(second, False, "dead endpoint " + self.urls[1])
        self.assertFalse(pool.refresh_due(309))
        self.assertTrue(pool.refresh_due(310))
        event, _ = self.refresh(pool, now=310)
        self.assertEqual(event["healthy_count"], 1)
        self.assertEqual(event["pending_count"], 1)
        self.assertEqual(pool.profile_ids, [first])
        self.assertNotEqual(pool.next_pending()[0], second)
        self.assertIsNone(pool.next_pending())
        with self.assertRaises(ValueError):
            pool.opener_by_id(second)
        pool.mark_checked(second, True)
        self.assertNotIn(second, pool.profile_ids)
        public = json.dumps(pool.snapshot())
        self.assertIn("excluded", public)
        self.assertNotIn(self.urls[1], public)
        self.assertNotIn("8.8.8.8:8080", public)

    def test_refresh_failure_keeps_healthy_and_does_not_log_provider_response(self):
        pool = self.auto()
        self.refresh(pool)
        identifier = pool.next_pending()[0]
        pool.mark_checked(identifier, True)
        with patch("src.tools.proxy_profiles.proxyscrape.fetch_candidates", side_effect=URLError("provider-secret")):
            event = pool.refresh(timeout=1, now=310)
        self.assertEqual(pool.profile_ids, [identifier])
        self.assertEqual(event["event"], "refresh_failed")
        self.assertNotIn("provider-secret", json.dumps(event))
        self.assertFalse(pool.refresh_due(311))

    def test_empty_refresh_retires_old_pool_and_redaction_is_retained(self):
        pool = self.auto()
        self.refresh(pool)
        identifier = pool.next_pending()[0]
        pool.mark_checked(identifier, True)
        self.refresh(pool, urls=[], now=310)
        self.assertEqual(pool.profile_ids, [])
        self.assertIsNone(pool.next_opener())
        self.assertIn(identifier, pool.all_profile_ids)
        self.assertEqual(pool.snapshot()["profiles"][0]["state"], "expired")
        self.assertNotIn(self.urls[0], pool.redact(self.urls[0]))

    def test_refresh_disabled_still_allows_initial_download(self):
        pool = self.auto(proxy_refresh_seconds=0)
        self.assertTrue(pool.refresh_due(0))
        self.refresh(pool)
        self.assertFalse(pool.refresh_due(1000000))

    def test_manual_health_mode_deduplicates_and_redacts_discarded_credentials(self):
        options = {
            "engine": "proxy_http", "allowed_origins": [self.target],
            "proxy_healthcheck_url": self.target + "/health",
            "proxy_profiles": [
                {"id": "first", "url": "http://user:secret@127.0.0.1:3128"},
                {"id": "alias", "url": "http://other:hidden@127.0.0.1:3128"},
            ],
        }
        pool = ProxyProfilePool.from_options(options, self.target)
        self.assertEqual(pool.all_profile_ids, ["first"])
        self.assertEqual(pool.count_limit, 1)
        self.assertEqual(pool.profile_ids, [])
        self.assertFalse(pool.refresh_due(999))
        self.assertEqual(pool.next_pending()[0], "first")
        pool.mark_checked("first", True)
        pool.exclude("first", "failed secret hidden 127.0.0.1:3128")
        public = json.dumps(pool.snapshot())
        for private in ("secret", "hidden", "127.0.0.1:3128"):
            self.assertNotIn(private, public)

    def test_auto_option_validation_is_bounded_and_scope_checked(self):
        invalid = [
            {"proxy_source": "anything"}, {"proxy_source": []},
            {"proxy_count": 0}, {"proxy_count": 9}, {"proxy_count": 1.5},
            {"proxy_candidate_limit": 101}, {"proxy_fetch_timeout_seconds": 31},
            {"proxy_check_timeout_seconds": 0}, {"proxy_refresh_seconds": 29},
            {"proxy_refresh_seconds": float("inf")},
            {"proxy_healthcheck_url": "https://outside.example/check"},
            {"proxy_healthcheck_url": "https://secret@authorized.example/check"},
            {"proxy_profiles": [{"id": "a", "url": self.urls[0]}]},
            {"proxy_profiles_env": "PROFILE_ENV"},
        ]
        with patch("src.tools.proxy_profiles.proxyscrape.fetch_candidates") as fetch:
            for options in invalid:
                with self.subTest(options=options), self.assertRaises(ValueError):
                    self.auto(**options)
            fetch.assert_not_called()

    def test_default_healthcheck_preserves_ipv6_and_nondefault_port(self):
        target = "https://[::1]:8443/some/path"
        pool = ProxyProfilePool.from_options({
            "engine": "proxy_http", "allowed_origins": ["https://[::1]:8443"],
            "proxy_source": "proxyscrape",
        }, target)
        self.assertEqual(pool.healthcheck_url, "https://[::1]:8443/robots.txt")

    def test_excluding_current_proxy_preserves_round_robin_next_identity(self):
        pool = self.auto(proxy_count=3)
        self.refresh(pool)
        for _ in range(3):
            pool.mark_checked(pool.next_pending()[0], True)
        first, second, third = pool.profile_ids
        self.assertEqual(pool.next_opener()[0], first)
        pool.exclude(first, "failed")
        self.assertEqual([pool.next_opener()[0] for _ in range(3)], [second, third, second])


if __name__ == "__main__":
    unittest.main()
