import unittest
from unittest.mock import patch

from actions.main import run


class TestPubkeyToAddressIntent(unittest.TestCase):
    @patch("actions.main._zbar_tools_installed", return_value=True)
    @patch("actions.main._qrencode_installed", return_value=True)
    @patch("actions.main._adilosjs_installed", return_value=True)
    @patch("actions.main._ecjsonrpc_installed", return_value=True)
    @patch("actions.main._secp256k1_installed", return_value=True)
    @patch("actions.main._ethers_js_installed", return_value=True)
    @patch("actions.main._pubkey_to_eth_address")
    def test_convert_pubkey_to_eth_address_success(
        self,
        mock_convert,
        _mock_ethers,
        _mock_secp,
        _mock_ecjsonrpc,
        _mock_adilos,
        _mock_qr,
        _mock_zbar,
    ):
        mock_convert.return_value = {
            "pubkey_uncompressed_hex": "0x" + "11" * 64,
            "eth_address": "0x" + "22" * 20,
        }

        result = run(intent="convert pubkey 0x" + "03" + "ab" * 32 + " to ethereum address")

        self.assertEqual(result["response"], "Converted EC public key to Ethereum address.")
        self.assertEqual(result["data"]["convert_pubkey"]["eth_address"], "0x" + "22" * 20)
        self.assertIn("local:secp256k1", result["data"]["sources"])
        self.assertIn("local:ethers", result["data"]["sources"])

    @patch("actions.main._zbar_tools_installed", return_value=True)
    @patch("actions.main._qrencode_installed", return_value=True)
    @patch("actions.main._adilosjs_installed", return_value=True)
    @patch("actions.main._ecjsonrpc_installed", return_value=True)
    @patch("actions.main._secp256k1_installed", return_value=False)
    def test_convert_pubkey_missing_dependencies(
        self,
        _mock_secp,
        _mock_ecjsonrpc,
        _mock_adilos,
        _mock_qr,
        _mock_zbar,
    ):
        result = run(intent="convert pubkey 0x" + "03" + "ab" * 32 + " to ethereum address")

        self.assertIn("requires Node modules secp256k1 and ethers", result["response"])
        self.assertEqual(result["data"]["convert_pubkey"]["secp256k1_installed"], False)


if __name__ == "__main__":
    unittest.main()
