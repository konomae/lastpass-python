# coding: utf-8
import unittest
from lastpass.session import Session


class SessionTestCase(unittest.TestCase):
    def setUp(self):
        self.id = '53ru,Hb713QnEVM5zWZ16jMvxS0'
        self.key_iteration_count = 5000

        self.session = Session(self.id, self.key_iteration_count)

    def test_id_returns_the_correct_value(self):
        self.assertEqual(self.session.id, self.id)

    def test_key_iteration_count_returns_the_correct_value(self):
        self.assertEqual(self.session.key_iteration_count, self.key_iteration_count)
