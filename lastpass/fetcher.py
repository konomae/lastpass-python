# coding: utf-8
import hashlib
from builtins import bytes
from base64 import b64decode
from binascii import hexlify
from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol.KDF import PBKDF2
import requests
from xml.etree import ElementTree as etree
from . import blob
from .exceptions import (
    NetworkError,
    InvalidResponseError,
    UnknownResponseSchemaError,
    LastPassUnknownUsernameError,
    LastPassInvalidPasswordError,
    LastPassIncorrectGoogleAuthenticatorCodeError,
    LastPassIncorrectYubikeyPasswordError,
    LastPassUnknownError
)
from .session import Session


def login(username, password, multifactor_password=None):
    key_iteration_count = request_iteration_count(username)
    return request_login(username, password, key_iteration_count, multifactor_password)


def fetch(session, web_client=requests):
    response = web_client.get('https://lastpass.com/getaccts.php?mobile=1&b64=1&hash=0.0&hasplugin=3.0.23&requestsrc=android',
                              cookies={'PHPSESSID': session.id})

    if response.status_code != requests.codes.ok:
        raise NetworkError()

    return blob.Blob(decode_blob(response.content), session.key_iteration_count)


def request_iteration_count(username, web_client=requests):
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


def request_login(username, password, key_iteration_count, multifactor_password=None, web_client=requests):
    body = {
        'method': 'mobile',
        'web': 1,
        'xml': 1,
        'username': username,
        'hash': make_hash(username, password, key_iteration_count),
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

    session = create_session(parsed_response, key_iteration_count)
    if not session:
        raise login_error(parsed_response)
    return session


def create_session(parsed_response, key_iteration_count):
    if parsed_response.tag == 'ok':
        session_id = parsed_response.attrib.get('sessionid')
        if isinstance(session_id, str):
            return Session(session_id, key_iteration_count)


def login_error(parsed_response):
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


def decode_blob(blob):
    return b64decode(blob)


def make_key(username, password, key_iteration_count):
    if key_iteration_count == 1:
        return hashlib.sha256(bytes(username, 'utf-8') + bytes(password, 'utf-8')).digest()
    else:
        prf = lambda p, s: HMAC.new(p, s, SHA256).digest()
        return PBKDF2(password, username, 32, key_iteration_count, prf)


def make_hash(username, password, key_iteration_count):
    if key_iteration_count == 1:
        return bytearray(hashlib.sha256(hexlify(make_key(username, password, 1)) + bytes(password, 'utf-8')).hexdigest(), 'ascii')
    else:
        prf = lambda p, s: HMAC.new(p, s, SHA256).digest()
        return hexlify(PBKDF2(
            make_key(username, password, key_iteration_count),
            bytes(password, 'utf-8'),
            32,
            1,
            prf))
