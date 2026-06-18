"""Shared httpx / respx fixtures for async HTTP provider testing."""
from collections.abc import Generator
from typing import Any

import httpx
import pytest
import respx


@pytest.fixture
def respx_mock_base_url() -> Generator[respx.MockRouter, None, None]:
    """
    A respx router with assert_all_called=False.
    Use when you want to stub specific routes and ignore the rest.

    Usage in a test:
        def test_something(respx_mock_base_url):
            respx_mock_base_url.get("http://127.0.0.1:11434/api/tags").mock(
                return_value=httpx.Response(200, json={"models": []})
            )
    """
    with respx.mock(assert_all_called=False) as router:
        yield router


@pytest.fixture
def mock_http_client(respx_mock_base_url: respx.MockRouter) -> httpx.AsyncClient:
    """
    An httpx.AsyncClient whose requests are intercepted by the respx mock.
    Pass this directly to provider constructors that accept a client parameter.

    The respx_mock_base_url fixture activates respx.mock(), which patches httpx's
    transport globally — so a plain AsyncClient is routed through the mock. (Do
    NOT pass the router as `transport=`; a MockRouter is not an httpx transport.)

    Usage:
        async def test_health(mock_http_client):
            respx_mock_base_url.get("http://127.0.0.1:11434/api/tags").mock(
                return_value=httpx.Response(200, json={"models": []})
            )
            provider = OllamaProvider(client=mock_http_client)
            assert await provider.health_check() is True
    """
    return httpx.AsyncClient()


def json_response(data: dict[str, Any], status: int = 200) -> httpx.Response:
    """Convenience: build a mock httpx.Response with a JSON body."""
    return httpx.Response(status, json=data)


def error_response(status: int, detail: str = "") -> httpx.Response:
    """Convenience: build a mock httpx.Response for error cases."""
    return httpx.Response(status, json={"detail": detail} if detail else {})
