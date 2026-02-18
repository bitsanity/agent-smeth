import unittest
from unittest.mock import patch

from actions.main import run


class TestCurrentPriceIntent(unittest.TestCase):
    @patch("actions.main._etherscan_get")
    def test_agent_smeth_gets_current_price_intent_uses_etherscan(self, mock_etherscan_get):
        mock_etherscan_get.return_value = {
            "status": "1",
            "message": "OK",
            "result": {"ethusd": "4242.69"},
        }

        result = run(
            intent="agent-smeth gets current price",
            etherscan_api_key="test-key",
            etherscan_api_url="https://etherscan.io",
        )

        self.assertEqual(result["response"], "Fetched ETH price via Etherscan (fallback path).")
        self.assertIn("data", result)
        self.assertEqual(result["data"]["price"]["price_usd"], "4242.69")
        self.assertIn("etherscan:stats.ethprice", result["data"]["sources"])
        mock_etherscan_get.assert_called_once_with(
            "https://etherscan.io",
            "test-key",
            {"module": "stats", "action": "ethprice"},
        )


if __name__ == "__main__":
    unittest.main()

