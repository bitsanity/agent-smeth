import unittest
from unittest.mock import patch

from actions.main import run


class TestBalanceIntent(unittest.TestCase):
    @patch("actions.main._jsonrpc")
    def test_balance_intent_returns_eth(self, mock_jsonrpc):
        # 1 ETH in wei
        mock_jsonrpc.return_value = hex(10**18)

        result = run(
            intent="get balance for address",
            rpc_url="https://rpc.example",
            from_="0x1111111111111111111111111111111111111111",
        )

        self.assertEqual(result["response"], "Fetched address balance via JSON-RPC.")
        self.assertEqual(result["data"]["balance"]["wei"], 10**18)
        self.assertEqual(result["data"]["balance"]["eth"], 1.0)
        self.assertEqual(result["data"]["balance"]["address"], "0x1111111111111111111111111111111111111111")
        mock_jsonrpc.assert_called_once_with(
            "https://rpc.example", "eth_getBalance", ["0x1111111111111111111111111111111111111111", "latest"]
        )


if __name__ == "__main__":
    unittest.main()
