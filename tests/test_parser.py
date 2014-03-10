# coding: utf-8
from base64 import b64decode
import unittest
from io import BytesIO
from lastpass.blob import Blob
from lastpass.chunk import Chunk
from lastpass.parser import Parser
from tests.test_data import TEST_BLOB, TEST_CHUNK_IDS, TEST_ACCOUNTS


class ParserTestCase(unittest.TestCase):
    def setUp(self):
        self.key_iteration_count = 5000
        self.blob = Blob(TEST_BLOB, self.key_iteration_count)
        self.padding = 'BEEFFACE'
        self.encryption_key = b64decode('OfOUvVnQzB4v49sNh4+PdwIFb9Fr5+jVfWRTf+E2Ghg=')

        self.chunks = Parser.extract_chunks(self.blob)
        self.accounts = [Parser.parse_account(i, self.encryption_key) for i in self.chunks['ACCT']]

    def test_extract_chunks_returns_chunks_as_a_dict(self):
        self.assertIsInstance(self.chunks, dict)

    def test_extract_chunks_all_keys_are_strings(self):
        self.assertListEqual(self.chunks.keys(), TEST_CHUNK_IDS)

    def test_extract_chunks_all_values_are_arrays(self):
        self.assertListEqual(list(set([type(v) for v in self.chunks.values()])), [list])

    def test_extract_chunks_all_arrays_contain_only_chunks(self):
        self.assertListEqual(list(set([type(c) for v in self.chunks.values() for c in v])), [Chunk])

    def test_extract_chunks_all_chunks_grouped_under_correct_ids(self):
        self.assertTrue(all([id == c.id for id, chunk_group in self.chunks.items() for c in chunk_group]))

    def test_parse_account_parses_account(self):
        self.assertListEqual([a.id for a in self.accounts], [a.id for a in TEST_ACCOUNTS])

    def test_read_chunk_returns_a_chunk(self):
        io = BytesIO(('4142434400000004DEADBEEF' + self.padding).decode('hex'))
        self.assertEqual(Parser.read_chunk(io), Chunk('ABCD', 'DEADBEEF'.decode('hex')))
        self.assertEqual(io.tell(), 12)

    def test_read_item_returns_an_item(self):
        io = BytesIO(('00000004DEADBEEF' + self.padding).decode('hex'))
        self.assertEqual(Parser.read_item(io), 'DEADBEEF'.decode('hex'))
        self.assertEqual(io.tell(), 8)

    def test_skip_item_skips_an_empty_item(self):
        io = BytesIO(('00000000' + self.padding).decode('hex'))
        Parser.skip_item(io)
        self.assertEqual(io.tell(), 4)

    def test_skip_item_skips_a_non_empty_item(self):
        io = BytesIO(('00000004DEADBEEF' + self.padding).decode('hex'))
        Parser.skip_item(io)
        self.assertEqual(io.tell(), 8)

    def test_read_id_returns_an_id(self):
        io = BytesIO('ABCD' + self.padding)
        self.assertEqual(Parser.read_id(io), 'ABCD')
        self.assertEqual(io.tell(), 4)

    def test_read_size_returns_a_size(self):
        io = BytesIO(('DEADBEEF' + self.padding).decode('hex'))
        self.assertEqual(Parser.read_size(io), 0xDEADBEEF)
        self.assertEqual(io.tell(), 4)

    def test_read_payload_returns_a_payload(self):
        io = BytesIO(('FEEDDEADBEEF' + self.padding).decode('hex'))
        self.assertEqual(Parser.read_payload(io, 6), 'FEEDDEADBEEF'.decode('hex'))
        self.assertEqual(io.tell(), 6)

    def test_read_uint32_returns_a_number(self):
        io = BytesIO(('DEADBEEF' + self.padding).decode('hex'))
        self.assertEqual(Parser.read_size(io), 0xDEADBEEF)
        self.assertEqual(io.tell(), 4)

    def test_decode_hex_decodes_hex(self):
        self.assertEqual(Parser.decode_hex(''), '')
        self.assertEqual(Parser.decode_hex('00ff'), '\x00\xFF')
        self.assertEqual(Parser.decode_hex('00010203040506070809'), '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09')
        self.assertEqual(Parser.decode_hex('000102030405060708090a0b0c0d0e0f'), '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F')
        self.assertEqual(Parser.decode_hex('8af633933e96a3c3550c2734bd814195'), '\x8A\xF6\x33\x93\x3E\x96\xA3\xC3\x55\x0C\x27\x34\xBD\x81\x41\x95')

    def test_decode_hex_raises_exception_on_odd_length(self):
        self.assertRaises(TypeError, Parser.decode_hex, '0')

    def test_decode_hex_raises_exception_on_invalid_characters(self):
        self.assertRaises(TypeError, Parser.decode_hex, 'xz')

    def test_decode_base64_decodes_base64(self):
        self.assertEqual(Parser.decode_base64(''), '')
        self.assertEqual(Parser.decode_base64('YQ=='), 'a')
        self.assertEqual(Parser.decode_base64('YWI='), 'ab')
        self.assertEqual(Parser.decode_base64('YWJj'), 'abc')
        self.assertEqual(Parser.decode_base64('YWJjZA=='), 'abcd')

    def test_decode_aes256_auto_decodes_a_blank_string(self):
        self.assertEqual(Parser.decode_aes256_auto('', self.encryption_key), '')

    def test_decode_aes256_auto_decodes_ecb_plain_string(self):
        self.assertEqual(Parser.decode_aes256_auto(
            b64decode('BNhd3Q3ZVODxk9c0C788NUPTIfYnZuxXfkghtMJ8jVM='), self.encryption_key),
            'All your base are belong to us')

    def test_decode_aes256_auto_decodes_ecb_base64_string(self):
        self.assertEqual(Parser.decode_aes256_auto(
            'BNhd3Q3ZVODxk9c0C788NUPTIfYnZuxXfkghtMJ8jVM=', self.encryption_key),
            'All your base are belong to us')

    def test_decode_aes256_auto_decodes_cbc_plain_string(self):
        self.assertEqual(Parser.decode_aes256_auto(
            b64decode('IcokDWmjOkKtLpZehWKL6666Uj6fNXPpX6lLWlou+1Lrwb+D3ymP6BAwd6C0TB3hSA=='), self.encryption_key),
            'All your base are belong to us')

    def test_decode_aes256_auto_decodes_cbc_base64_string(self):
        self.assertEqual(Parser.decode_aes256_auto(
            '!YFuiAVZgOD2K+s6y8yaMOw==|TZ1+if9ofqRKTatyUaOnfudletslMJ/RZyUwJuR/+aI=', self.encryption_key),
            'All your base are belong to us')

    def test_decode_aes256_ecb_plain_decodes_a_blank_string(self):
        self.assertEqual(Parser.decode_aes256_ecb_plain(
            b64decode(''), self.encryption_key),
            '')

    def test_decode_aes256_ecb_plain_decodes_a_short_string(self):
        self.assertEqual(Parser.decode_aes256_ecb_plain(
            b64decode('8mHxIA8rul6eq72a/Gq2iw=='), self.encryption_key),
            '0123456789')

    def test_decode_aes256_ecb_plain_decodes_a_long_string(self):
        self.assertEqual(Parser.decode_aes256_ecb_plain(
            b64decode('BNhd3Q3ZVODxk9c0C788NUPTIfYnZuxXfkghtMJ8jVM='), self.encryption_key),
            'All your base are belong to us')

    def test_decode_aes256_ecb_base64_decodes_a_blank_string(self):
        self.assertEqual(Parser.decode_aes256_ecb_base64(
            '', self.encryption_key),
            '')

    def test_decode_aes256_ecb_base64_decodes_a_short_string(self):
        self.assertEqual(Parser.decode_aes256_ecb_base64(
            '8mHxIA8rul6eq72a/Gq2iw==', self.encryption_key),
            '0123456789')

    def test_decode_aes256_ecb_base64_decodes_a_long_string(self):
        self.assertEqual(Parser.decode_aes256_ecb_base64(
            'BNhd3Q3ZVODxk9c0C788NUPTIfYnZuxXfkghtMJ8jVM=', self.encryption_key),
            'All your base are belong to us')

    def test_decode_aes256_cbc_plain_decodes_a_blank_string(self):
        self.assertEqual(Parser.decode_aes256_cbc_plain(
            b64decode(''), self.encryption_key),
            '')

    def test_decode_aes256_cbc_plain_decodes_a_short_string(self):
        self.assertEqual(Parser.decode_aes256_cbc_plain(
            b64decode('IQ+hiIy0vGG4srsHmXChe3ehWc/rYPnfiyqOG8h78DdX'), self.encryption_key),
            '0123456789')

    def test_decode_aes256_cbc_plain_decodes_a_long_string(self):
        self.assertEqual(Parser.decode_aes256_cbc_plain(
            b64decode('IcokDWmjOkKtLpZehWKL6666Uj6fNXPpX6lLWlou+1Lrwb+D3ymP6BAwd6C0TB3hSA=='), self.encryption_key),
            'All your base are belong to us')

    def test_decode_aes256_cbc_base64_decodes_a_blank_string(self):
        self.assertEqual(Parser.decode_aes256_cbc_base64(
            '', self.encryption_key),
            '')

    def test_decode_aes256_cbc_base64_decodes_a_short_string(self):
        self.assertEqual(Parser.decode_aes256_cbc_base64(
            '!6TZb9bbrqpocMaNgFjrhjw==|f7RcJ7UowesqGk+um+P5ug==', self.encryption_key),
            '0123456789')

    def test_decode_aes256_cbc_base64_decodes_a_long_string(self):
        self.assertEqual(Parser.decode_aes256_cbc_base64(
            '!YFuiAVZgOD2K+s6y8yaMOw==|TZ1+if9ofqRKTatyUaOnfudletslMJ/RZyUwJuR/+aI=', self.encryption_key),
            'All your base are belong to us')
