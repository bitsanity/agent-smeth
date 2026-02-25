import unittest
from unittest.mock import patch

from actions.main import run


class TestAdilosAgentPubkeyIntent(unittest.TestCase):
    @patch("actions.main._zbar_tools_installed", return_value=True)
    @patch("actions.main._qrencode_installed", return_value=True)
    @patch("actions.main._adilosjs_installed", return_value=True)
    @patch("actions.main._ecjsonrpc_installed", return_value=True)
    @patch("actions.main._adilos_make_challenge")
    def test_obtain_connecting_agent_pubkey_intent_generates_challenge(
        self,
        mock_make_challenge,
        _mock_ecjsonrpc,
        _mock_adilos,
        _mock_qr,
        _mock_zbar,
    ):
        mock_make_challenge.return_value = {
            "sessionkey_hex": "cd" * 32,
            "challenge_base64": "ADILOS_AGENT_CHALLENGE_BASE64",
        }

        result = run(intent="obtain connecting agent public key over websocket using adilos")

        self.assertEqual(
            result["response"],
            "Generated an ADILOS challenge for connecting-agent pubkey exchange.",
        )
        self.assertEqual(result["data"]["adilos"]["intent"], "obtain-agent-pubkey")
        self.assertEqual(result["data"]["adilos"]["sessionkey_hex"], "cd" * 32)
        self.assertEqual(result["data"]["adilos"]["challenge_base64"], "ADILOS_AGENT_CHALLENGE_BASE64")
        self.assertIn("Send challenge_base64", result["data"]["adilos"]["next_steps"][0])


if __name__ == "__main__":
    unittest.main()
