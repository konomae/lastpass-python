# coding: utf-8
from base64 import b64decode
import unittest
from lastpass.blob import Blob


class BlobTestCase(unittest.TestCase):
    def setUp(self):
        self.bytes = b64decode('TFBBVgAAAAMxMjJQUkVNAAAACjE0MTQ5')
        self.key_iteration_count = 500
        self.username = 'postlass@gmail.com'
        self.password = 'pl1234567890'
        self.encryption_key = b64decode('OfOUvVnQzB4v49sNh4+PdwIFb9Fr5+jVfWRTf+E2Ghg=')

        self.blob = Blob(self.bytes, self.key_iteration_count)

    def test_bytes_returns_the_correct_value(self):
        self.assertEqual(self.blob.bytes, self.bytes)

    def test_key_iteration_count_returns_the_correct_value(self):
        self.assertEqual(self.blob.key_iteration_count, self.key_iteration_count)

    def test_encryption_key_returns_the_correct_value(self):
        self.assertEqual(self.blob.encryption_key(self.username, self.password), self.encryption_key)
