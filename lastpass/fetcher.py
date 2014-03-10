# coding: utf-8
import hashlib
from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol.KDF import PBKDF2
import requests
#from lxml import etree
from xml.etree import ElementTree as etree
import blob 
from exceptions import (
    NetworkError,
    InvalidResponseError,
    UnknownResponseSchemaError,
    LastPassUnknownUsernameError,
    LastPassInvalidPasswordError,
    LastPassIncorrectGoogleAuthenticatorCodeError,
    LastPassIncorrectYubikeyPasswordError,
    LastPassUnknownError
)
from session import Session


class Fetcher(object):
    @classmethod
    def login(cls, username, password, multifactor_password=None):
        key_iteration_count = cls.request_iteration_count(username)
        return cls.request_login(username, password, key_iteration_count, multifactor_password)

    @classmethod
    def fetch(cls, session, web_client=requests):
        response = web_client.get('https://lastpass.com/getaccts.php?mobile=1&b64=1&hash=0.0',
                                  cookies={'PHPSESSID': session.id})

        if response.status_code != requests.codes.ok:
            raise NetworkError()

        return blob.Blob(cls.decode_blob(response.content), session.key_iteration_count)

    @classmethod
    def request_iteration_count(cls, username, web_client=requests):
        response = web_client.post('https://lastpass.com/iterations.php',
                                   data={'email': username})
        if response.status_code != requests.codes.ok:
            raise NetworkError()

        try:
            count = int(response.content)
        except:
            raise InvalidResponseError('Key iteration count is invalid')

        if count > 0:
            return count
        raise InvalidResponseError('Key iteration count is not positive')

    @classmethod
    def request_login(cls, username, password, key_iteration_count, multifactor_password=None, web_client=requests):
        body = {
            'method': 'mobile',
            'web': 1,
            'xml': 1,
            'username': username,
            'hash': cls.make_hash(username, password, key_iteration_count),
            'iterations': key_iteration_count,
        }

        if multifactor_password:
            body['otp'] = multifactor_password

        response = web_client.post('https://lastpass.com/login.php',
                                   data=body)

        if response.status_code != requests.codes.ok:
            raise NetworkError()

        try:
            parsed_response = etree.fromstring(response.content)
        except etree.ParseError:
            parsed_response = None

        if parsed_response is None:
            raise InvalidResponseError()

        session = cls.create_session(parsed_response, key_iteration_count)
        if not session:
            raise cls.login_error(parsed_response)
        return session

    @classmethod
    def create_session(cls, parsed_response, key_iteration_count):
        if parsed_response.tag == 'ok':
            session_id = parsed_response.attrib.get('sessionid')
            if isinstance(session_id, basestring):
                return Session(session_id, key_iteration_count)

    @classmethod
    def login_error(cls, parsed_response):
        error = None if parsed_response.tag != 'response' else parsed_response.find('error')
        if error is None or len(error.attrib) == 0:
            raise UnknownResponseSchemaError()

        exceptions = {
            "unknownemail": LastPassUnknownUsernameError,
            "unknownpassword": LastPassInvalidPasswordError,
            "googleauthrequired": LastPassIncorrectGoogleAuthenticatorCodeError,
            "googleauthfailed": LastPassIncorrectGoogleAuthenticatorCodeError,
            "yubikeyrestricted": LastPassIncorrectYubikeyPasswordError,
        }

        cause = error.attrib.get('cause')
        message = error.attrib.get('message')

        if cause:
            return exceptions.get(cause, LastPassUnknownError)(message or cause)
        return InvalidResponseError(message)

    @classmethod
    def decode_blob(cls, blob):
        return blob.decode('base64')

    @classmethod
    def make_key(cls, username, password, key_iteration_count):
        if key_iteration_count == 1:
            return hashlib.sha256(username + password).digest()
        else:
            prf = lambda p, s: HMAC.new(p, s, SHA256).digest()
            return PBKDF2(password, username, 32, key_iteration_count, prf)

    @classmethod
    def make_hash(cls, username, password, key_iteration_count):
        if key_iteration_count == 1:
            return hashlib.sha256(cls.make_key(username, password, 1).encode('hex') + password).hexdigest()
        else:
            prf = lambda p, s: HMAC.new(p, s, SHA256).digest()
            return PBKDF2(
                cls.make_key(username, password, key_iteration_count),
                password,
                32,
                1,
                prf).encode('hex')

