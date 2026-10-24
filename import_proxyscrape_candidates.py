"""Display unverified HTTP candidates from the fixed official ProxyScrape API.

This script only downloads and normalizes proxy URLs. It does not test
third-party destinations, update .env, or start a fuzzing scan.

Usage from FuzzingTool project root:
    python import_proxyscrape_candidates.py --limit 20
"""
from __future__ import annotations

import argparse
from src.tools.proxyscrape import MAX_BYTES, SOURCE_URL, fetch_candidates, parse_http_proxy_urls


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=20, help="Number of candidates to display (1..100)")
    parser.add_argument("--timeout", type=float, default=10, help="API timeout in seconds (0.01..30)")
    args = parser.parse_args()
    if not 1 <= args.limit <= 100:
        parser.error("--limit must be between 1 and 100")
    try:
        candidates = fetch_candidates(timeout=args.timeout, limit=args.limit)
    except (OSError, ValueError) as exc:
        print(f"Could not obtain proxy candidates: {type(exc).__name__}")
        return 1
    print(f"HTTP public proxy candidates: {len(candidates)} (unverified locally)")
    for proxy in candidates[:args.limit]:
        print(proxy)
    print("\nUse proxy_http with proxy_source=proxyscrape to check candidates within the scan budget.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
