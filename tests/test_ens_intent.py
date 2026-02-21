import unittest
from unittest.mock import patch

from actions.main import run


class TestEnsIntent(unittest.TestCase):
    @patch("actions.main._zbar_tools_installed", return_value=True)
    @patch("actions.main._ens_resolve")
    def test_find_ens_name_from_intent_text(self, mock_ens_resolve, _mock_zbar_check):
        mock_ens_resolve.return_value = {
            "address": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
            "name": "vitalik.eth",
            "displayName": "vitalik.eth",
            "avatar": "https://metadata.ens.domains/mainnet/avatar/vitalik.eth",
        }

        result = run(intent="find vitalik.eth in ENS")

        self.assertEqual(result["response"], "Resolved ENS name(s).")
        self.assertIn("ens-api:resolve", result["data"]["sources"])
        self.assertEqual(
            result["data"]["ens"]["resolved"]["vitalik.eth"]["address"],
            "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
        )

    @patch("actions.main._zbar_tools_installed", return_value=True)
    @patch("actions.main._ens_resolve", side_effect=RuntimeError("not found"))
    def test_find_ens_name_handles_resolution_error(self, _mock_ens_resolve, _mock_zbar_check):
        result = run(intent="find noone.eth in ENS")

        self.assertEqual(result["response"], "I couldn't resolve the ENS name(s).")
        self.assertIn("noone.eth", result["data"]["ens"]["errors"])


if __name__ == "__main__":
    unittest.main()
