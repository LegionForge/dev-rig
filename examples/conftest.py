# Example conftest.py for a consuming project.
# Copy this to your project's tests/ directory and adjust imports.
#
# This re-exports the shared fixtures from legionforge_dev_rig so that
# pytest discovers them automatically — no imports needed in individual tests.

from legionforge_dev_rig.fixtures import mock_http_client, respx_mock_base_url

__all__ = ["mock_http_client", "respx_mock_base_url"]
