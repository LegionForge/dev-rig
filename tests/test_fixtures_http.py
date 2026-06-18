"""Tests for the shared httpx/respx fixtures shipped by the dev-rig.

These also serve as the rig's own self-test target so test.yml is validated
end-to-end against the rig itself (see .github/workflows/ci.yml).
"""
import httpx
import pytest

from legionforge_dev_rig.fixtures import http as fx


def test_json_response_defaults() -> None:
    resp = fx.json_response({"ok": True})
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}


def test_json_response_custom_status() -> None:
    resp = fx.json_response({"created": 1}, status=201)
    assert resp.status_code == 201
    assert resp.json() == {"created": 1}


def test_error_response_with_detail() -> None:
    resp = fx.error_response(404, "missing")
    assert resp.status_code == 404
    assert resp.json() == {"detail": "missing"}


def test_error_response_without_detail() -> None:
    resp = fx.error_response(500)
    assert resp.status_code == 500
    assert resp.json() == {}


def test_respx_fixture_stubs_route(respx_mock_base_url) -> None:
    respx_mock_base_url.get("http://svc.local/ping").mock(
        return_value=httpx.Response(200, json={"pong": True})
    )
    # respx.mock() is active via the fixture; a plain client is intercepted.
    with httpx.Client() as client:
        r = client.get("http://svc.local/ping")
    assert r.json() == {"pong": True}


@pytest.mark.asyncio
async def test_mock_http_client_is_async_and_wired(
    mock_http_client, respx_mock_base_url
) -> None:
    respx_mock_base_url.get("http://svc.local/health").mock(
        return_value=httpx.Response(200, json={"status": "ok"})
    )
    async with mock_http_client as client:
        r = await client.get("http://svc.local/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}
