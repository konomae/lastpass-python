# coding: utf-8
import pbkdf2
import hashlib
import requests
#from lxml import etree
from xml.etree import ElementTree as etree


class Fetcher(object):
    @classmethod
    def fetch(cls, username, password, iterations=1):
        fetcher = cls(username, password, iterations)
        fetcher._fetch()

        return fetcher

    @staticmethod
    def make_key(username, password, iterations=1):
        if iterations == 1:
            return hashlib.sha256(username + password).digest()
        else:
            return pbkdf2.pbkdf2_bin(password, username, iterations, 32, hashlib.sha256)

    @classmethod
    def make_hash(cls, username, password, iterations=1):
        if iterations == 1:
            return hashlib.sha256(cls.make_key(username, password, 1).encode('hex') + password).hexdigest()
        else:
            return pbkdf2.pbkdf2_hex(
                cls.make_key(username, password, iterations),
                password,
                1,
                32,
                hashlib.sha256)

    def __init__(self, username, password, iterations):
        self.username = username
        self.password = password
        self.iterations = iterations

    def _fetch(self):
        self.blob = self._fetch_blob(self._login())

    def _login(self):
        self.encryption_key = Fetcher.make_key(self.username, self.password, self.iterations)
        options = {
            'method': 'mobile',
            'xml': 1,
            'username': self.username,
            'hash': self.make_hash(self.username, self.password, self.iterations),
            'iterations': self.iterations,
        }

        url = 'https://lastpass.com/login.php'
        return self._handle_login_response(requests.post(url, data=options))

    def _handle_login_response(self, response):
        if response.status_code != requests.codes['OK']:
            raise RuntimeError('Failed to login: "{}"'.format(response))
        parsed_response = etree.fromstring(response.content)

        if parsed_response.tag == 'ok':
            return parsed_response.attrib['sessionid']

        if parsed_response.tag == 'response':
            error = parsed_response.find('error')
            if error.attrib.get('iterations'):
                self.iterations = int(error.attrib['iterations'])
                return self._login()
            elif error.attrib.get('message'):
                raise RuntimeError('Failed to login, LastPass says "{}"'.format(error.attrib['message']))
            else:
                raise RuntimeError('Failed to login, LastPass responded with an unknown error')
        else:
            raise RuntimeError('Failed to login, the reason is unknown')

    def _fetch_blob(self, session_id):
        url = 'https://lastpass.com/getaccts.php?mobile=1&b64=1&hash=0.0'
        response = requests.get(url, cookies={'PHPSESSID': session_id})

        response.raise_for_status()
        return response.content
