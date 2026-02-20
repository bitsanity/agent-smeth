import unittest
from unittest.mock import patch

from actions.main import run


class TestGasPriceIntent(unittest.TestCase):
    @patch("actions.main._jsonrpc")
    def test_gas_price_intent_returns_gwei(self, mock_jsonrpc):
        # 50 gwei in wei = 50 * 1e9
        mock_jsonrpc.return_value = hex(50 * 10**9)

        result = run(
            intent="get current ethereum gas price",
            rpc_url="https://rpc.example",
        )

        self.assertEqual(result["response"], "Fetched current gas price via JSON-RPC.")
        self.assertIn("data", result)
        self.assertEqual(result["data"]["gas"]["wei"], 50 * 10**9)
        self.assertEqual(result["data"]["gas"]["gwei"], 50.0)
        mock_jsonrpc.assert_called_once_with("https://rpc.example", "eth_gasPrice", [])


if __name__ == "__main__":
    unittest.main()
