"""Replay wordlist generation from saved Recon; never scan the target website."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import time
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ["PYTHON_DOTENV_DISABLED"] = "1"
os.environ["LANGCHAIN_TRACING_V2"] = "false"
os.environ["LANGSMITH_TRACING"] = "false"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--recon", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    recon_path, out = args.recon.resolve(), args.output.resolve()
    if not out.is_relative_to(ROOT) or out == ROOT:
        parser.error("Choose an output subdirectory within this project")
    if (out / "02_wordlist_result.json").exists() or (out / "logs/llm_responses.jsonl").exists():
        parser.error("Output already contains a run; choose a new directory")
    recon_bytes = recon_path.read_bytes()
    recon = json.loads(recon_bytes)

    from dotenv import dotenv_values

    settings = dotenv_values(ROOT / ".env", interpolate=False)
    key = os.environ.get("DEEPSEEK_API_KEY") or settings.get("DEEPSEEK_API_KEY")
    if not key:
        parser.error("DEEPSEEK_API_KEY is not configured")
    base_url = os.environ.get("DEEPSEEK_BASE_URL") or settings.get("DEEPSEEK_BASE_URL") or "https://api.deepseek.com"
    parsed = urlsplit(base_url)
    if (parsed.scheme, parsed.hostname, parsed.port or 443) != ("https", "api.deepseek.com", 443) or parsed.username or parsed.password or parsed.query or parsed.fragment:
        parser.error("This replay uses only the previously authorized https://api.deepseek.com origin")
    # Make the exact key available to the local log redactor, never to a log row.
    os.environ["DEEPSEEK_API_KEY"] = key
    model = os.environ.get("LLM_MODEL") or settings.get("LLM_MODEL") or "deepseek-flash"
    temperature = float(os.environ.get("LLM_TEMPERATURE") or settings.get("LLM_TEMPERATURE") or "0.1")
    out.mkdir(parents=True, exist_ok=True)
    shutil.copytree(ROOT / "knowledge", out / "knowledge", dirs_exist_ok=True)
    os.chdir(out)
    os.environ["LLM_RESPONSE_LOG_FILE"] = str(out / "logs/llm_responses.jsonl")

    from langchain_openai import ChatOpenAI
    from src.agents.wordlist_gen import WordlistGenAgent
    from src.coordinator.llm_logging import sanitize_for_log

    llm = ChatOpenAI(api_key=key, base_url=base_url, model=model,
                     temperature=temperature, timeout=60, max_retries=1)
    stack = dict(recon.get("tech_stack") or {})
    stack["target_url"] = recon.get("target_url", "")
    manifest = {
        "started_at_utc": datetime.now(timezone.utc).isoformat(),
        "recon_file": str(recon_path), "recon_sha256": hashlib.sha256(recon_bytes).hexdigest(),
        "target_url": stack["target_url"], "target_http_requests": 0,
        "llm_origin": "https://api.deepseek.com", "llm_model": model,
        "response_log": str(out / "logs/llm_responses.jsonl"),
        "note": "Wordlist-only replay from saved Recon, no Bearer needed, no fuzzing or target requests.",
    }
    (out / "run_manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Wordlist-only replay; target HTTP requests: 0; response log: {manifest['response_log']}", flush=True)
    started = time.monotonic()
    try:
        result = WordlistGenAgent(llm=llm).execute(
            tech_stack=stack, discovered_paths=recon.get("discovered_paths", []),
            js_endpoints=recon.get("js_endpoints", []),
        )
    except Exception as exc:
        failure = sanitize_for_log({"error_type": type(exc).__name__, "error": str(exc)})
        (out / "error.json").write_text(json.dumps(failure, indent=2), encoding="utf-8")
        print(json.dumps(failure), flush=True)
        return 1
    for name in ("02_wordlist_result.json", "02_pattern_trace.json", "target_profile.json", "02_parameter_wordlist.txt"):
        shutil.copy2(out / "output_samples" / name, out / name)
    rows = [json.loads(line) for line in (out / "logs/llm_responses.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    summary = {
        "duration_seconds": round(time.monotonic() - started, 2),
        "wordlist_count": len(result.get("wordlist", [])),
        "generation_strategy": result.get("generation_strategy"),
        "llm_enriched_parts": result.get("assembler_metadata", {}).get("llm_enriched_parts", {}),
        "application_level_llm_records": len(rows),
        "target_http_requests": 0,
    }
    (out / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False), flush=True)
    print(f"Saved outputs: {out}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
