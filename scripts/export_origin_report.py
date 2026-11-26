"""B5 CLI: offline, verified export of a finished local multi-origin session.

Reads the recovery journal, its anchored checkpoints and the final `pipeline` checkpoint, then writes
report.json (canonical envelope), report.md (rendered from the envelope) and manifest.json into a new
directory. Sends no HTTP, calls no LLM, writes no KnowledgeStore and never runs resume/finalize_only.

Usage:
    export_origin_report.py <recovery_dir> [--output DIR]

Exit codes: 0 exported; 2 refused (public reason code on stdout); 3 write failure.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("PYTHON_DOTENV_DISABLED", "1")

from src.coordinator.origin_export import ExportError, export_session  # noqa: E402


def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline B5 export of a finished local multi-origin session")
    parser.add_argument("recovery_dir", help="session recovery directory (journal.jsonl, head.json, session.lock)")
    parser.add_argument("--output", help="new output directory (must not exist); "
                                         "default: <session root>/b5_export_<UTC timestamp>")
    args = parser.parse_args(argv)
    directory = Path(args.recovery_dir).resolve()
    output = Path(args.output) if args.output else directory.parent / (
        "b5_export_" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
    try:
        result = export_session(directory, output)
    except ExportError as exc:
        print(json.dumps({"exported": False, "code": exc.code}), flush=True)
        return 3 if exc.code == "export_write_failed" else 2
    print(json.dumps({"exported": True, "output": result["output"], "export_digest": result["export_digest"],
                      "report_digest": result["report_digest"], "pipeline_status": result["pipeline_status"]}), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
