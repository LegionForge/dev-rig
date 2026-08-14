# Example: testing an async HTTP provider using the shared mock fixtures.
# Replace MyProvider with your actual provider class.
#
# This file is NOT part of the dev-rig test suite — it is a template.
# Copy to your project's tests/unit/ and adapt.

import httpx
import respx

# from myproject.providers.myservice import MyProvider  # ← uncomment in your project


class _FakeProvider:
    """Stand-in for documentation purposes only."""

    def __init__(self, base_url: str, client: httpx.AsyncClient) -> None:
        self._base_url = base_url
        self._client = client

    async def health_check(self) -> bool:
        try:
            r = await self._client.get(f"{self._base_url}/health")
            return r.status_code == 200
        except httpx.HTTPError:
            return False


# ── Tests using shared fixtures ───────────────────────────────────────────────


class TestProviderHealthCheck:
    async def test_healthy_service_returns_true(
        self,
        mock_http_client: httpx.AsyncClient,
        respx_mock_base_url: respx.MockRouter,
    ) -> None:
        respx_mock_base_url.get("http://127.0.0.1:9999/health").mock(
            return_value=httpx.Response(200)
        )
        provider = _FakeProvider("http://127.0.0.1:9999", mock_http_client)
        assert await provider.health_check() is True

    async def test_unhealthy_service_returns_false(
        self,
        mock_http_client: httpx.AsyncClient,
        respx_mock_base_url: respx.MockRouter,
    ) -> None:
        respx_mock_base_url.get("http://127.0.0.1:9999/health").mock(
            return_value=httpx.Response(503)
        )
        provider = _FakeProvider("http://127.0.0.1:9999", mock_http_client)
        assert await provider.health_check() is False

    async def test_network_error_returns_false(
        self,
        mock_http_client: httpx.AsyncClient,
        respx_mock_base_url: respx.MockRouter,
    ) -> None:
        respx_mock_base_url.get("http://127.0.0.1:9999/health").mock(
            side_effect=httpx.ConnectError("connection refused")
        )
        provider = _FakeProvider("http://127.0.0.1:9999", mock_http_client)
        assert await provider.health_check() is False
