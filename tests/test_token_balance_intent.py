import unittest
from unittest.mock import patch

from actions.main import run


class TestTokenBalanceIntent(unittest.TestCase):
    @patch("actions.main._jsonrpc")
    def test_token_balance_intent_calls_eth_call(self, mock_jsonrpc):
        # return 1000 (0x3e8)
        mock_jsonrpc.return_value = "0x3e8"

        addr = "0x1111111111111111111111111111111111111111"
        token = "0x2222222222222222222222222222222222222222"

        result = run(
            intent="get token balance",
            rpc_url="https://rpc.example",
            from_=addr,
            token=token,
        )

        self.assertEqual(result["response"], "Fetched ERC-20 token balance via JSON-RPC.")
        self.assertEqual(result["data"]["token_balance"]["address"], addr)
        self.assertEqual(result["data"]["token_balance"]["token"], token)
        self.assertEqual(result["data"]["token_balance"]["raw"], 1000)

        expected_data = "0x70a08231" + ("0" * 24) + addr[2:]
        mock_jsonrpc.assert_called_once_with(
            "https://rpc.example",
            "eth_call",
            [{"to": token, "data": expected_data}, "latest"],
        )


if __name__ == "__main__":
    unittest.main()
