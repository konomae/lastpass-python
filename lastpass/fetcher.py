# coding: utf-8
import hashlib
import json
from base64 import b64decode
from binascii import hexlify
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

http = requests


def login(username, password, multifactor_password=None, client_id=None):
    key_iteration_count = request_iteration_count(username)
    return request_login(username, password, key_iteration_count, multifactor_password, client_id)


def logout(session, web_client=http):
    # type: (Session, requests) -> None
    response = web_client.get(
        'https://lastpass.com/logout.php?mobile=1',
        cookies={'PHPSESSID': session.id}
    )

    if response.status_code != requests.codes.ok:
        raise NetworkError()


def fetch_authenticator(session, web_client=http):
    return fetch_override(session,
                          web_client,
                          'https://lastpass.com/lmiapi/authenticator/backup',
                          headers={
                              'X-CSRF-TOKEN': session.csrf_token,
                              'X-SESSION-ID': session.id,
                          },
                          decode_json=True)


def fetch(session, web_client=http):
    return fetch_override(session,
                          web_client,
                          'https://lastpass.com/getaccts.php?mobile=1&b64=1&hash=0.0&hasplugin=3.0.23&requestsrc=android',
                          cookies={'PHPSESSID': session.id})

def fetch_override(session,
                   web_client=http,
                   url='https://lastpass.com/getaccts.php?mobile=1&b64=1&hash=0.0&hasplugin=3.0.23&requestsrc=android',
                   cookies=None,
                   headers=None,
                   decode_json=False):
    response = web_client.get(url, cookies=cookies, headers=headers)

    if response.status_code != requests.codes.ok:
        raise NetworkError()

    if decode_json:
        if 'content-type' in response.headers and response.headers['content-type'].startswith('application/json'):
            data = json.loads(response.content)
            return blob.Blob(data['userData'].encode('utf-8'), session.key_iteration_count)
        else:
            raise InvalidResponseError('Expected JSON response')
    else:
        return blob.Blob(decode_blob(response.content), session.key_iteration_count)


def request_iteration_count(username, web_client=http):
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


def request_login(username, password, key_iteration_count, multifactor_password=None, client_id=None, web_client=http):
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

    if client_id:
        body['imei'] = client_id

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
        csrf_token = parsed_response.attrib.get('token')
        if isinstance(session_id, str):
            return Session(session_id, key_iteration_count, csrf_token)


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
    # type: (str, str, int) -> bytes
    if key_iteration_count == 1:
        return hashlib.sha256(username.encode('utf-8') + password.encode('utf-8')).digest()
    else:
        return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), username.encode('utf-8'), key_iteration_count,
                                   32)


def make_hash(username, password, key_iteration_count):
    # type: (str, str, int) -> bytes
    if key_iteration_count == 1:
        return bytearray(
            hashlib.sha256(hexlify(make_key(username, password, 1)) + password.encode('utf-8')).hexdigest(), 'ascii')
    else:
        return hexlify(hashlib.pbkdf2_hmac(
            'sha256',
            make_key(username, password, key_iteration_count),
            password.encode('utf-8'),
            1,
            32
        ))
