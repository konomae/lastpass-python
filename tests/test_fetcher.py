# coding: utf-8
from base64 import b64decode
import unittest
import mock
import lastpass
from lastpass.blob import Blob
from lastpass import fetcher
from lastpass.session import Session


class FetcherTestCase(unittest.TestCase):
    def setUp(self):
        self.username = 'username'
        self.password = 'password'
        self.key_iteration_count = 5000

        self.hash = b'7880a04588cfab954aa1a2da98fd9c0d2c6eba4c53e36a94510e6dbf30759256'
        self.session_id = '53ru,Hb713QnEVM5zWZ16jMvxS0'
        self.session = Session(self.session_id, self.key_iteration_count)

        self.blob_response = 'TFBBVgAAAAMxMjJQUkVNAAAACjE0MTQ5'
        self.blob_bytes = b64decode(self.blob_response)
        self.blob = Blob(self.blob_bytes, self.key_iteration_count)

        self.login_post_data = {'method': 'mobile',
                                'web': 1,
                                'xml': 1,
                                'username': self.username,
                                'hash': self.hash,
                                'iterations': self.key_iteration_count}

        self.device_id = '492378378052455'
        self.login_post_data_with_device_id = self.login_post_data.copy()
        self.login_post_data_with_device_id.update({'imei': self.device_id})

        self.google_authenticator_code = '12345'
        self.yubikey_password = 'emdbwzemyisymdnevznyqhqnklaqheaxszzvtnxjrmkb'

        self.login_post_data_with_google_authenticator_code = self.login_post_data.copy()
        self.login_post_data_with_google_authenticator_code['otp'] = self.google_authenticator_code

        self.login_post_data_with_yubikey_password = self.login_post_data.copy()
        self.login_post_data_with_yubikey_password['otp'] = self.yubikey_password

    def test_logout_makes_a_get_request(self):
        m = mock.Mock()
        m.get.return_value = self._http_ok('')
        fetcher.logout(self.session, m)
        m.get.assert_called_with(
            'https://lastpass.com/logout.php?mobile=1',
            cookies={'PHPSESSID': self.session_id}
        )

    def test_logout_raises_an_exception_on_HTTP_error(self):
        m = mock.Mock()
        m.post.return_value = self._http_error()
        self.assertRaises(lastpass.NetworkError, fetcher.logout, self.session, m)

    def test_request_iteration_count_makes_a_post_request(self):
        m = mock.Mock()
        m.get.return_value = self._http_ok(str(self.key_iteration_count))
        fetcher.request_iteration_count(self.username, m)
        m.get.assert_called_with('https://lastpass.com/iterations.php',
                                  params={'email': self.username},
                                  headers=fetcher.headers)

    def test_request_iteration_count_returns_key_iteration_count(self):
        m = mock.Mock()
        m.get.return_value = self._http_ok(str(self.key_iteration_count))
        self.assertEqual(fetcher.request_iteration_count(self.username, m), self.key_iteration_count)

    def test_request_iteration_count_raises_an_exception_on_http_error(self):
        m = mock.Mock()
        m.get.return_value = self._http_error()
        self.assertRaises(lastpass.NetworkError, fetcher.request_iteration_count, self.username, m)

    def test_request_iteration_count_raises_an_exception_on_invalid_key_iteration_count(self):
        m = mock.Mock()
        m.get.return_value = self._http_ok('not a number')
        self.assertRaises(lastpass.InvalidResponseError, fetcher.request_iteration_count, self.username, m)

    def test_request_iteration_count_raises_an_exception_on_zero_key_iteration_cont(self):
        m = mock.Mock()
        m.get.return_value = self._http_ok('0')
        self.assertRaises(lastpass.InvalidResponseError, fetcher.request_iteration_count, self.username, m)

    def test_request_iteration_count_raises_an_exception_on_negative_key_iteration_cont(self):
        m = mock.Mock()
        m.get.return_value = self._http_ok('-1')
        self.assertRaises(lastpass.InvalidResponseError, fetcher.request_iteration_count, self.username, m)

    def test_request_login_makes_a_post_request(self):
        self._verify_request_login_post_request(None, None, self.login_post_data)

    def test_request_login_makes_a_post_request_with_device_id(self):
        self._verify_request_login_post_request(None, self.device_id, self.login_post_data_with_device_id)

    def test_request_login_makes_a_post_request_with_google_authenticator_code(self):
        self._verify_request_login_post_request(self.google_authenticator_code,
                                                None,
                                                self.login_post_data_with_google_authenticator_code)

    def test_request_login_makes_a_post_request_with_yubikey_password(self):
        self._verify_request_login_post_request(self.yubikey_password,
                                                None,
                                                self.login_post_data_with_yubikey_password)

    def test_request_login_returns_a_session(self):
        self.assertEqual(self._request_login_with_xml('<ok sessionid="{}" />'.format(self.session_id)), self.session)

    def test_request_login_raises_an_exception_on_http_error(self):
        self.assertRaises(lastpass.NetworkError, self._request_login_with_error)

    def test_request_login_raises_an_exception_when_response_is_not_a_hash(self):
        self.assertRaises(lastpass.InvalidResponseError, self._request_login_with_ok, 'not a hash')

    def test_request_login_raises_an_exception_on_unknown_response_schema_1(self):
        self.assertRaises(lastpass.UnknownResponseSchemaError, self._request_login_with_xml, '<unknown />')

    def test_request_login_raises_an_exception_on_unknown_response_schema_2(self):
        self.assertRaises(lastpass.UnknownResponseSchemaError, self._request_login_with_xml, '<response />')

    def test_request_login_raises_an_exception_on_unknown_response_schema_3(self):
        self.assertRaises(lastpass.UnknownResponseSchemaError,
                          self._request_login_with_xml, '<response><error /></response>')

    def test_request_login_raises_an_exception_on_unknown_username(self):
        self.assertRaises(lastpass.LastPassUnknownUsernameError,
                          self._request_login_with_lastpass_error, 'unknownemail')

    def test_request_login_raises_an_exception_on_invalid_password(self):
        self.assertRaises(lastpass.LastPassInvalidPasswordError,
                          self._request_login_with_lastpass_error, 'unknownpassword')

    def test_request_login_raises_an_exception_on_missing_google_authenticator_code(self):
        message = 'Google Authenticator authentication required! ' \
                  'Upgrade your browser extension so you can enter it.'
        self.assertRaises(lastpass.LastPassIncorrectGoogleAuthenticatorCodeError,
                          self._request_login_with_lastpass_error, 'googleauthrequired', message)

    def test_request_login_raises_an_exception_on_incorrect_google_authenticator_code(self):
        message = 'Google Authenticator authentication failed!'
        self.assertRaises(lastpass.LastPassIncorrectGoogleAuthenticatorCodeError,
                          self._request_login_with_lastpass_error, 'googleauthfailed', message)

    def test_request_login_raises_an_exception_on_missing_or_incorrect_yubikey_password(self):
        message = 'Your account settings have restricted you from logging in ' \
                  'from mobile devices that do not support YubiKey authentication.'
        self.assertRaises(lastpass.LastPassIncorrectYubikeyPasswordError,
                          self._request_login_with_lastpass_error, 'yubikeyrestricted', message)

    def test_request_login_raises_an_exception_on_unknown_lastpass_error_without_a_message(self):
        cause = 'Unknown cause'
        self.assertRaises(lastpass.LastPassUnknownError,
                          self._request_login_with_lastpass_error, cause)

    def test_fetch_makes_a_get_request(self):
        m = mock.Mock()
        m.get.return_value = self._http_ok(self.blob_response)
        fetcher.fetch(self.session, m)
        m.get.assert_called_with('https://lastpass.com/getaccts.php?mobile=1&b64=1&hash=0.0&hasplugin=3.0.23&requestsrc=android',
                                 cookies={'PHPSESSID': self.session_id})

    def test_fetch_returns_a_blob(self):
        m = mock.Mock()
        m.get.return_value = self._http_ok(self.blob_response)
        self.assertEqual(fetcher.fetch(self.session, m), self.blob)

    def test_fetch_raises_exception_on_http_error(self):
        m = mock.Mock()
        m.get.return_value = self._http_error()
        self.assertRaises(lastpass.NetworkError, fetcher.fetch, self.session, m)

    def test_make_key_generates_correct_keys(self):
        keys = [
            (1, b64decode('C/Bh2SGWxI8JDu54DbbpV8J9wa6pKbesIb9MAXkeF3Y=')),
            (5, b64decode('pE9goazSCRqnWwcixWM4NHJjWMvB5T15dMhe6ug1pZg=')),
            (10, b64decode('n9S0SyJdrMegeBHtkxUx8Lzc7wI6aGl+y3/udGmVey8=')),
            (50, b64decode('GwI8/kNy1NjIfe3Z0VAZfF78938UVuCi6xAL3MJBux0=')),
            (100, b64decode('piGdSULeHMWiBS3QJNM46M5PIYwQXA6cNS10pLB3Xf8=')),
            (500, b64decode('OfOUvVnQzB4v49sNh4+PdwIFb9Fr5+jVfWRTf+E2Ghg=')),
            (1000, b64decode('z7CdwlIkbu0XvcB7oQIpnlqwNGemdrGTBmDKnL9taPg=')),
        ]

        for iterations, key in keys:
            self.assertEqual(key, fetcher.make_key('postlass@gmail.com', 'pl1234567890', iterations))

    def test_make_hash(self):
        hashes = [
            (1, b'a1943cfbb75e37b129bbf78b9baeab4ae6dd08225776397f66b8e0c7a913a055'),
            (5, b'a95849e029a7791cfc4503eed9ec96ab8675c4a7c4e82b00553ddd179b3d8445'),
            (10, b'0da0b44f5e6b7306f14e92de6d629446370d05afeb1dc07cfcbe25f169170c16'),
            (50, b'1d5bc0d636da4ad469cefe56c42c2ff71589facb9c83f08fcf7711a7891cc159'),
            (100, b'82fc12024acb618878ba231a9948c49c6f46e30b5a09c11d87f6d3338babacb5'),
            (500, b'3139861ae962801b59fc41ff7eeb11f84ca56d810ab490f0d8c89d9d9ab07aa6'),
            (1000, b'03161354566c396fcd624a424164160e890e96b4b5fa6d942fc6377ab613513b'),
        ]

        for iterations, hash in hashes:
            self.assertEqual(hash, fetcher.make_hash('postlass@gmail.com', 'pl1234567890', iterations))

    def _verify_request_login_post_request(self, multifactor_password, device_id, post_data):
        m = mock.Mock()
        m.post.return_value = self._http_ok('<ok sessionid="{}" />'.format(self.session_id))
        fetcher.request_login(self.username, self.password, self.key_iteration_count, multifactor_password, device_id, m)
        m.post.assert_called_with('https://lastpass.com/login.php',
                                  data=post_data,
                                  headers=fetcher.headers)

    @staticmethod
    def _mock_response(code, body):
        m = mock.Mock()
        m.status_code = code
        m.content = body
        return m

    def _http_ok(self, body):
        return self._mock_response(200, body)

    def _http_error(self, body=''):
        return self._mock_response(404, body)

    @staticmethod
    def _lastpass_error(cause, message):
        if message:
            return '<response><error cause="{}" message="{}" /></response>'.format(cause, message)
        return '<response><error cause="{}" /></response>'.format(cause)

    def _request_login_with_lastpass_error(self, cause, message=None):
        return self._request_login_with_xml(self._lastpass_error(cause, message))

    def _request_login_with_xml(self, text):
        return self._request_login_with_ok(text)

    def _request_login_with_ok(self, response):
        return self._request_login_with_response(self._http_ok(response))

    def _request_login_with_error(self):
        return self._request_login_with_response(self._http_error())

    def _request_login_with_response(self, response):
        m = mock.Mock()
        m.post.return_value = response
        return fetcher.request_login(self.username, self.password, self.key_iteration_count, None, None, m)
