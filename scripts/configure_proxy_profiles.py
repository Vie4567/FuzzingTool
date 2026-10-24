"""Save operator-provided proxy profiles locally without displaying credentials.

This checks syntax and scope only. It does not connect to a proxy or target,
discover endpoints, or establish that public egress addresses differ.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
from pathlib import Path
import sys
import warnings


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from dotenv import set_key

_proxy_dotenv_state = os.environ.get("PYTHON_DOTENV_DISABLED")
os.environ["PYTHON_DOTENV_DISABLED"] = "1"
try:
    from src.tools.proxy_profiles import ProxyProfilePool, _origin
finally:
    if _proxy_dotenv_state is None:
        os.environ.pop("PYTHON_DOTENV_DISABLED", None)
    else:
        os.environ["PYTHON_DOTENV_DISABLED"] = _proxy_dotenv_state


PROFILE_ENV = "FUZZ_PROXY_PROFILES"


def _origin_url(target):
    scheme, host, port = _origin(target, origin_only=True)
    host = f"[{host}]" if ":" in host else host
    suffix = "" if port == (443 if scheme == "https" else 80) else f":{port}"
    return f"{scheme}://{host}{suffix}"


def _env_path(raw):
    candidate = Path(raw)
    candidate = candidate if candidate.is_absolute() else PROJECT_ROOT / candidate
    candidate = candidate.resolve()
    if candidate == PROJECT_ROOT or not candidate.is_relative_to(PROJECT_ROOT):
        raise ValueError("The environment file must stay inside the project")
    if candidate.is_dir():
        raise ValueError("The environment file must be a file")
    return candidate


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="https://cab.vn", help="Exact authorized HTTP(S) origin")
    parser.add_argument("--profiles", type=int, default=2, choices=range(2, 9), metavar="2..8")
    parser.add_argument("--env-file", default=".env", help="Environment file inside the project")
    args = parser.parse_args(argv)
    try:
        origin = _origin_url(args.target)
        env_path = _env_path(args.env_file)
    except (ValueError, OSError):
        print("Invalid target origin or environment file; no changes saved.", flush=True)
        return 2

    print(f"Local configuration for {origin}; no network check will run.", flush=True)
    print("Enter your own HTTP proxy URLs, including port. Input is hidden.", flush=True)
    profiles = []
    try:
        # Stop instead of allowing getpass to fall back to echoed input.
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            for index in range(args.profiles):
                identifier = f"egress-{chr(ord('a') + index)}"
                url = getpass.getpass(f"Proxy URL for {identifier}: ")
                profiles.append({"id": identifier, "url": url})
    except KeyboardInterrupt:
        print("Configuration cancelled; no changes saved.", flush=True)
        return 130
    except (EOFError, getpass.GetPassWarning):
        print("Use an interactive terminal with hidden input; no changes saved.", flush=True)
        return 2

    try:
        pool = ProxyProfilePool.from_options(
            {"engine": "proxy_http", "proxy_profiles": profiles, "allowed_origins": [origin]},
            origin,
        )
    except (ValueError, TypeError):
        print("Invalid or duplicate proxy endpoints; no changes saved. Use distinct http://host:port endpoints.", flush=True)
        return 2

    try:
        saved, _, _ = set_key(
            env_path, PROFILE_ENV, json.dumps(profiles, ensure_ascii=False),
            quote_mode="always", encoding="utf-8",
        )
        if not saved:
            raise OSError("Environment setting was not saved")
    except OSError:
        print("Could not save the environment file; check its path and write access.", flush=True)
        return 1

    print(f"Saved {PROFILE_ENV}; profiles: {', '.join(pool.profile_ids)}.", flush=True)
    print("Other environment settings are preserved. No network request was made.", flush=True)
    print("Next, run from the project directory:", flush=True)
    # Windows PowerShell command; origin has already been validated, but quote
    # single quotes to keep operator-supplied hostnames literal in the shell.
    quoted_origin = "'" + origin.replace("'", "''") + "'"
    print(
        ".\\.venv\\Scripts\\python.exe -B .\\scripts\\run_proxy_http_check.py "
        f"--target {quoted_origin}", flush=True,
    )
    if env_path != PROJECT_ROOT / ".env":
        print("The runner reads the project .env or process environment; this custom file is not loaded automatically.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
