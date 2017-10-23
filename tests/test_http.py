# coding: utf-8
import unittest
import requests
from lastpass import fetcher


class HttpTestCase(unittest.TestCase):
    def setUp(self):
        pass

    def test_can_set_the_proxy_options(self):
        self.assertIsNotNone(fetcher.http)
        fetcher.http = requests.session()
        fetcher.http.proxies = {
            'http': 'http://ffazbear:itsme@proxy.fazbearentertainment.com:1987',
            'https': 'https://ffazbear:itsme@proxy.fazbearentertainment.com:1987',
        }

        self.assertEqual(
            fetcher.http.proxies['https'],
            'https://ffazbear:itsme@proxy.fazbearentertainment.com:1987'
        )
