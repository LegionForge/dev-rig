# Re-export the shared fixtures so pytest discovers them in the rig's own
# self-test suite (mirrors the consuming-project pattern in examples/conftest.py).
from legionforge_dev_rig.fixtures import mock_http_client, respx_mock_base_url

__all__ = ["mock_http_client", "respx_mock_base_url"]
