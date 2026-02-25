import unittest
from unittest.mock import patch

from actions.main import run


class TestAdilosHumanPubkeyIntent(unittest.TestCase):
    @patch("actions.main._zbar_tools_installed", return_value=True)
    @patch("actions.main._qrencode_installed", return_value=True)
    @patch("actions.main._adilosjs_installed", return_value=True)
    @patch("actions.main._ecjsonrpc_installed", return_value=True)
    @patch("actions.main._adilos_make_challenge")
    @patch("actions.main._render_qr_png", return_value="/tmp/agent-smeth-qr-adilos.png")
    def test_obtain_human_pubkey_intent_generates_challenge_qr(
        self,
        _mock_render,
        mock_make_challenge,
        _mock_ecjsonrpc,
        _mock_adilos,
        _mock_qr,
        _mock_zbar,
    ):
        mock_make_challenge.return_value = {
            "sessionkey_hex": "ab" * 32,
            "challenge_base64": "ADILOS_CHALLENGE_BASE64",
        }

        result = run(intent="obtain human pubkey with adilos qr challenge")

        self.assertEqual(
            result["response"],
            "Generated an ADILOS challenge QR to obtain the human EC public key.",
        )
        self.assertEqual(result["data"]["adilos"]["intent"], "obtain-human-pubkey")
        self.assertEqual(result["data"]["adilos"]["sessionkey_hex"], "ab" * 32)
        self.assertEqual(result["data"]["adilos"]["challenge_base64"], "ADILOS_CHALLENGE_BASE64")
        self.assertEqual(result["data"]["adilos"]["challenge_qr_png_path"], "/tmp/agent-smeth-qr-adilos.png")


if __name__ == "__main__":
    unittest.main()
