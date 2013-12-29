# coding: utf-8
import unittest
from lastpass.chunk import Chunk


class ChunkTestCase(unittest.TestCase):
    def setUp(self):
        self.id = 'IDID'
        self.payload = 'Payload'

        self.chunk = Chunk(self.id, self.payload)

    def test_id_returns_the_correct_value(self):
        self.assertEqual(self.chunk.id, self.id)

    def test_payload_returns_the_correct_value(self):
        self.assertEqual(self.chunk.payload, self.payload)
