"""Per-run Recon measurements. This layer never initiates additional requests."""

from datetime import datetime, timezone
from threading import Lock

from src.coordinator.runtime import current_runtime


CHANNELS = ("CH-1 Headers", "CH-2 DOM", "CH-3 JS", "CH-4 Spider",
            "CH-5 Probe", "CH-6 Schema", "CH-7 Error")


def _stats():
    return dict(attempted_requests=0, responses_received=0, network_errors=0,
                response_read_errors=0, bytes_received=0)


class ReconRecords:
    def __init__(self, transport):
        self.transport = transport
        self.channels = {name: {"status": "skipped", "stats": _stats(),
                                "errors": [], "reason": "not_started"} for name in CHANNELS}
        self.requests = []
        self.errors = []
        self.stop_reason = None
        self.lock = Lock()

    def stopped(self):
        budget = current_runtime()
        if budget:
            try:
                budget.check()
            except TimeoutError:
                pass
            if budget.stop_reason:
                self.stop_reason = budget.stop_reason
        return self.stop_reason is not None

    def start(self, channel):
        if self.stopped():
            self.channels[channel]["reason"] = self.stop_reason
            return False
        self.channels[channel].update(status="running", reason=None)
        return True

    def finish(self, channel):
        data = self.channels[channel]
        if data["status"] == "skipped":
            return
        if data["errors"]:
            shared = self.channels.get(data.get("shared_response_channel"), {})
            received = data["stats"]["responses_received"] or shared.get("stats", {}).get("responses_received", 0)
            data["status"] = "partial" if received else "failed"
        else:
            data["status"] = "partial" if self.stopped() else "completed"

    def error(self, channel, error_type, message, **details):
        error = {"agent": "tech_recon", "channel": channel, "error_type": error_type,
                 "message": self.transport.redact(str(message)), "count": 1,
                 "timestamp": datetime.now(timezone.utc).isoformat(), **details}
        error = self.transport.redact(error)
        with self.lock:
            self.errors.append(error)
            self.channels[channel]["errors"].append(error)

    def observe(self, channel, result):
        with self.lock:
            stats = self.channels[channel]["stats"]
            stats["attempted_requests"] += int(result["attempted"])
            stats["responses_received"] += int(result["status_code"] is not None)
            stats["network_errors"] += int(result["attempted"] and result["status_code"] is None)
            stats["response_read_errors"] += int(result["status_code"] is not None and bool(result["error"]))
            stats["bytes_received"] += result["bytes_received"]
            public = {key: result[key] for key in (
                "url", "method", "attempted", "status_code", "body_complete",
                "content_length", "bytes_received", "body_truncated", "response_time", "stop_reason")}
            public.update(channel=channel, classification="observed")
            self.requests.append(self.transport.redact(public))
            if result.get("stop_reason"):
                self.stop_reason = result["stop_reason"]
        if result["error"]:
            error = result["error"]
            self.error(channel, error["error_type"], error["message"],
                       url=result["url"], method=result["method"],
                       status_code=result["status_code"], attempted=result["attempted"])

    def for_channel(self, channel):
        return _ChannelTransport(self, channel)

    def execution(self):
        self.stopped()
        stats = _stats()
        for channel in self.channels.values():
            for key in stats:
                stats[key] += channel["stats"][key]
        incomplete = any(c["status"] in {"partial", "failed"} for c in self.channels.values())
        if not stats["responses_received"]:
            status = "failed"
        elif self.stop_reason or incomplete or self.errors:
            status = "partial"
        else:
            status = "completed"
        stop = self.stop_reason or ("transport_error" if stats["network_errors"] else
                                   "channel_error" if self.errors else "completed")
        return {"status": status, "success": status == "completed", "completed": status == "completed",
                "partial": status == "partial", "stop_reason": stop, "stats": stats,
                "count_scope": "Recon channel dispatches; optional login dispatches remain in global telemetry",
                "channels": self.channels, "errors": self.errors, "requests": self.requests}


class _ChannelTransport:
    def __init__(self, records, channel):
        self.records, self.channel = records, channel

    def __getattr__(self, name):
        return getattr(self.records.transport, name)

    def fetch(self, url, timeout=10, method="GET"):
        if self.records.stopped():
            return None, {}, "Recon stopped before dispatch"
        result = self.records.transport.fetch_result(url, timeout=timeout, method=method)
        self.records.observe(self.channel, result)
        # Incomplete body is retained as measurement, never parsed as complete input.
        return result["status_code"], result["headers"], result["body"] if result["body_complete"] else ""

    def error(self, error_type, message, **details):
        self.records.error(self.channel, error_type, message, **details)
