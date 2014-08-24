# coding: utf-8
import unittest
from lastpass.blob import Blob
from lastpass.vault import Vault
from tests.test_data import TEST_BLOB, TEST_KEY_ITERATION_COUNT, TEST_ENCRYPTION_KEY, TEST_ACCOUNTS


class VaultTestCase(unittest.TestCase):
    def setUp(self):
        self.vault = Vault(Blob(TEST_BLOB, TEST_KEY_ITERATION_COUNT), TEST_ENCRYPTION_KEY)

    def test_accounts_type_is_collect(self):
        self.assertIsInstance(self.vault.accounts, list)

    def test_accounts_have_correct_ids(self):
        self.assertListEqual([a.id for a in self.vault.accounts], [a.id for a in TEST_ACCOUNTS])
