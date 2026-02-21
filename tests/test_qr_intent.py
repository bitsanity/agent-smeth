import unittest
from unittest.mock import patch

from actions.main import run


class TestQrIntent(unittest.TestCase):
    @patch("actions.main._zbar_tools_installed", return_value=True)
    @patch("actions.main._qrencode_installed", return_value=True)
    @patch("actions.main._adilosjs_installed", return_value=True)
    @patch("actions.main._render_qr_png", return_value="/tmp/agent-smeth-qr-test.png")
    def test_show_qr_that_says_message(self, _mock_render, _mock_adilos, _mock_qr, _mock_zbar):
        result = run(intent="show me a qr code at the command line that says Hello World")

        self.assertEqual(result["response"], "Rendered QR code image for reliable scanning.")
        self.assertEqual(result["data"]["qr"]["message"], "Hello World")
        self.assertEqual(result["data"]["qr"]["path"], "/tmp/agent-smeth-qr-test.png")
        self.assertEqual(result["data"]["qr"]["format"], "PNG")

    @patch("actions.main._zbar_tools_installed", return_value=True)
    @patch("actions.main._qrencode_installed", return_value=True)
    @patch("actions.main._adilosjs_installed", return_value=True)
    @patch("actions.main._render_qr_png", return_value="/tmp/agent-smeth-qr-test.png")
    def test_say_with_qr_code_intent(self, _mock_render, _mock_adilos, _mock_qr, _mock_zbar):
        result = run(intent="say Hello World with a qr code")

        self.assertEqual(result["response"], "Rendered QR code image for reliable scanning.")
        self.assertEqual(result["data"]["qr"]["message"], "Hello World")


if __name__ == "__main__":
    unittest.main()
