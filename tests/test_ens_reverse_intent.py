import unittest
from unittest.mock import patch

from actions.main import run


class TestEnsReverseIntent(unittest.TestCase):
    @patch("actions.main._zbar_tools_installed", return_value=True)
    @patch("actions.main._ens_resolve")
    def test_reverse_lookup_compacts_whitespace_in_input_and_output(self, mock_ens_resolve, _mock_zbar_check):
        mock_ens_resolve.return_value = {
            "address": "0xdc8D255E709EdF2ed2622B2691E8E D9a71abB59E",
            "ens": "launchpad.eth",
            "ens_primary": "launchpad.eth",
            "resolverAddress": "0x4976fb03C32e5B8cfe2b6cCB31c09Ba78EBa Ba41",
        }

        result = run(intent='reverse ENS lookup 0xdc8D255E709EdF2ed2622B2691E8E D9a71abB59E')

        self.assertEqual(result["response"], "Resolved ENS reverse lookup.")
        self.assertEqual(
            result["data"]["ens_reverse"]["address"],
            "0xdc8D255E709EdF2ed2622B2691E8ED9a71abB59E",
        )
        self.assertEqual(
            result["data"]["ens_reverse"]["resolver_address"],
            "0x4976fb03C32e5B8cfe2b6cCB31c09Ba78EBaBa41",
        )


if __name__ == "__main__":
    unittest.main()
