# coding: utf-8
import unittest
from lastpass.account import Account


class AccountTestCase(unittest.TestCase):
    def setUp(self):
        self.id = 'id'
        self.name = 'name'
        self.username = 'username'
        self.password = 'password'
        self.url = 'url'
        self.group = 'group'
        self.notes = 'notes'
        self.account = Account(self.id, self.name, self.username, self.password, self.url, self.group, self.notes)

    def test_id_returns_the_correct_value(self):
        self.assertEqual(self.account.id, self.id)

    def test_name_returns_the_correct_value(self):
        self.assertEqual(self.account.name, self.name)

    def test_username_returns_the_correct_value(self):
        self.assertEqual(self.account.username, self.username)

    def test_password_returns_the_correct_value(self):
        self.assertEqual(self.account.password, self.password)

    def test_url_returns_the_correct_value(self):
        self.assertEqual(self.account.url, self.url)

    def test_group_returns_the_correct_value(self):
        self.assertEqual(self.account.group, self.group)

    def test_notes_returns_the_correct_value(self):
        self.assertEqual(self.account.notes, self.notes)
