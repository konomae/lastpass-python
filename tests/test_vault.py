# coding: utf-8
import unittest

import struct

from lastpass import InvalidResponseError
from lastpass.blob import Blob
from lastpass.vault import Vault
from tests.test_data import TEST_BLOB, TEST_KEY_ITERATION_COUNT, TEST_ENCRYPTION_KEY, TEST_ACCOUNTS


class VaultTestCase(unittest.TestCase):
    def setUp(self):
        self.vault = Vault(Blob(TEST_BLOB, TEST_KEY_ITERATION_COUNT), TEST_ENCRYPTION_KEY)

    def test_init_raises_an_exception_on_truncated_blob(self):
        for i in [1, 2, 3, 4, 5, 10, 100, 1000]:
            blob = Blob(TEST_BLOB[:-i], TEST_KEY_ITERATION_COUNT)
            with self.assertRaises(Exception) as context:
                Vault(blob, TEST_ENCRYPTION_KEY)

            self.assertIn(type(context.exception), [InvalidResponseError, struct.error])
            # self.assertEqual(context.exception.message, 'Blob is truncated')

    def test_accounts_type_is_collect(self):
        self.assertIsInstance(self.vault.accounts, list)

    def test_accounts_have_correct_ids(self):
        self.assertListEqual([a.id for a in self.vault.accounts], [a.id for a in TEST_ACCOUNTS])
