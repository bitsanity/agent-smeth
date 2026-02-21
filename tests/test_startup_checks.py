import unittest
from unittest.mock import patch

from actions.main import run


class TestStartupChecks(unittest.TestCase):
    @patch("actions.main._zbar_tools_installed", return_value=False)
    def test_startup_fails_when_zbar_tools_missing(self, _mock_zbar_check):
        result = run(intent="agent-smeth gets current price")

        self.assertIn("Startup check failed: zbar-tools is not installed", result["response"])
        self.assertEqual(result["data"]["startup_check"]["zbar_tools_installed"], False)

    @patch("actions.main._zbar_tools_installed", return_value=True)
    @patch("actions.main._adilosjs_installed", return_value=False)
    def test_startup_fails_when_adilosjs_missing(self, _mock_adilosjs_check, _mock_zbar_check):
        result = run(intent="agent-smeth gets current price")

        self.assertIn("Startup check failed: adilosjs npm module is not installed", result["response"])
        self.assertEqual(result["data"]["startup_check"]["adilosjs_installed"], False)

    @patch("actions.main._zbar_tools_installed", return_value=True)
    @patch("actions.main._adilosjs_installed", return_value=True)
    @patch("actions.main._etherscan_get")
    def test_startup_passes_when_checks_present(self, mock_etherscan_get, _mock_adilosjs_check, _mock_zbar_check):
        mock_etherscan_get.return_value = {
            "status": "1",
            "message": "OK",
            "result": {"ethusd": "4242.69"},
        }

        result = run(
            intent="agent-smeth gets current price",
            etherscan_api_key="test-key",
            etherscan_api_url="https://api.etherscan.io/v2/api/",
        )

        self.assertEqual(result["response"], "Fetched ETH price via Etherscan (fallback path).")
        self.assertEqual(result["data"]["price"]["price_usd"], "4242.69")


if __name__ == "__main__":
    unittest.main()
