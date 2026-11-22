"""Cancelable, elapsed-time limits for Coordinator model invocations.

HTTPX's read timeout resets when bytes arrive. A slow response can therefore
outlive that timeout indefinitely. Each non-streaming invocation also has an
async deadline; cancellation closes its private HTTP client before returning.
"""
import asyncio
from concurrent.futures import Future
from contextvars import copy_context
from threading import Thread
from urllib.parse import urlsplit

import httpx
from langchain_openai import ChatOpenAI
from .runtime import cap_timeout, check_deadline, current_runtime


class DeadlineChatOpenAI(ChatOpenAI):
    # The Coordinator consumes complete responses. Route LangChain .stream()
    # helpers through invoke too, so their transport cannot bypass this limit.
    disable_streaming: bool = True

    def _get_request_payload(self, input_, *, stop=None, **kwargs):
        payload = super()._get_request_payload(input_, stop=stop, **kwargs)
        # LangChain renames this to the OpenAI-specific completion limit.
        # DeepSeek's Chat Completions API documents max_tokens instead:
        # https://api-docs.deepseek.com/api/create-chat-completion/
        if urlsplit(str(self.openai_api_base or "")).hostname == "api.deepseek.com":
            if "max_completion_tokens" in payload:
                payload["max_tokens"] = payload.pop("max_completion_tokens")
        return payload

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        check_deadline()

        def run():
            return asyncio.run(self._agenerate(messages, stop=stop, **kwargs))

        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return run()

        # A sync agent may be called from an async crawler. Its private loop
        # lives in an owned thread with the same runtime/telemetry context.
        # Join unconditionally: no orphan request may continue after timeout.
        context, outcome = copy_context(), Future()

        def bridge():
            try:
                outcome.set_result(context.run(run))
            except BaseException as exc:
                outcome.set_exception(exc)

        worker = Thread(target=bridge, name="coordinator-llm-call")
        worker.start()
        worker.join()
        return outcome.result()

    async def _agenerate(self, messages, stop=None, run_manager=None, **kwargs):
        check_deadline()
        requested_timeout = float(self.request_timeout or 30)
        seconds = cap_timeout(requested_timeout)
        pipeline_limited = seconds < requested_timeout
        kwargs["timeout"] = seconds
        kwargs["stream"] = False

        async def call():
            # Never reuse a loop-bound client between asyncio.run invocations.
            # Copying the SDK settings preserves credentials/base URL/default
            # headers while giving this call its own cancellable connection.
            async with httpx.AsyncClient(proxy=self.openai_proxy or None,
                                         timeout=seconds, follow_redirects=False) as transport:
                client = self.root_async_client.with_options(
                    http_client=transport, timeout=seconds, max_retries=0,
                )
                model = self.model_copy(update={"root_async_client": client,
                                                "async_client": client.chat.completions})
                return await ChatOpenAI._agenerate(model, messages, stop=stop, **kwargs)

        try:
            # wait_for awaits cancellation; the async context closes the
            # connection before a timeout is exposed to callbacks/the caller.
            result = await asyncio.wait_for(call(), timeout=seconds)
        except asyncio.TimeoutError as exc:
            budget = current_runtime()
            if pipeline_limited and budget is not None and not budget.stop_reason:
                # Windows asyncio timers can fire within one clock tick before
                # time.monotonic reaches the deadline. The limiting budget is
                # still the pipeline, not an unrelated per-model timeout.
                budget.stop_reason = "pipeline_deadline"
            check_deadline()  # Preserve pipeline_deadline when it was limiting.
            raise TimeoutError("LLM elapsed-time limit exceeded") from exc
        check_deadline()
        return result
