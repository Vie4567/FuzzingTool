"""Unit tests must fail even if application code swallows a network error."""

import httpx
import pytest


@pytest.fixture(autouse=True)
def forbid_real_http(monkeypatch):
    attempted = []

    async def deny_async(self, request):
        attempted.append(str(request.url))
        raise AssertionError("Unit test attempted unmocked HTTP")

    def deny_sync(self, request):
        attempted.append(str(request.url))
        raise AssertionError("Unit test attempted unmocked HTTP")

    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", deny_async)
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", deny_sync)
    yield
    assert not attempted, f"Unmocked HTTP requests: {attempted}"
