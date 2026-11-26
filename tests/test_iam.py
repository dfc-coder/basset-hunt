"""Exercise the owner-side adapter with provider-shaped responses."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "adapters"))
import refresh_iam


class IamTests(unittest.TestCase):
    def setUp(self) -> None:
        self.account = "123456789012"
        self.binding = dict(iam_user="build", key_id="A" * 20, fingerprint="a" * 64,
                            owner="platform", permissions=["read"])
        self.manifest = dict(account=self.account, keys=[self.binding])

    def test_status_and_cache(self) -> None:
        self.manifest["keys"].extend([
            {**self.binding, "key_id": "B" * 20, "fingerprint": "b" * 64},
            {**self.binding, "key_id": "C" * 20, "fingerprint": "c" * 64},
        ])
        reply = {"AccessKeyMetadata": [
            {"UserName": "build", "AccessKeyId": "A" * 20, "Status": "Active"},
            {"UserName": "build", "AccessKeyId": "B" * 20, "Status": "Inactive"},
        ]}
        with patch.object(refresh_iam, "aws", side_effect=[{"Account": self.account}, reply]) as call:
            records = refresh_iam.refresh(self.manifest, "audit")
        self.assertEqual([r["state"] for r in records], ["active", "inactive"])
        self.assertEqual(call.call_count, 2)
        self.assertEqual(records[0]["permissions"], ["read"])

    def test_wrong_account(self) -> None:
        with patch.object(refresh_iam, "aws", return_value={"Account": "0" * 12}) as call:
            with self.assertRaises(ValueError):
                refresh_iam.refresh(self.manifest, "audit")
        self.assertEqual(call.call_count, 1)

    def test_incomplete_response(self) -> None:
        with patch.object(refresh_iam, "aws", side_effect=[{"Account": self.account}, {"IsTruncated": True}]):
            with self.assertRaises(ValueError):
                refresh_iam.refresh(self.manifest, "audit")


if __name__ == "__main__":
    unittest.main()
