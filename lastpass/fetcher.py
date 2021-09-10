# coding: utf-8
import hashlib
from base64 import b64decode
from binascii import hexlify
import requests
from xml.etree import ElementTree as etree
from . import blob
from .version import __version__
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
default_url = 'https://lastpass.com'
headers = {'user-agent': 'lastpass-python/{}'.format(__version__)}


def login(username, password, multifactor_password=None, client_id=None):
    key_iteration_count = request_iteration_count(username)
    return request_login(username, password, key_iteration_count, multifactor_password, client_id)
 

def logout(session, web_client=http):
    # type: (Session, requests) -> None 
    response = web_client.get(
        f'{session.url}/logout.php?mobile=1',
        cookies={'PHPSESSID': session.id}
    )

    if response.status_code != requests.codes.ok:
        raise NetworkError()


def fetch(session, web_client=http):
    response = web_client.get(f'{session.url}/getaccts.php?mobile=1&b64=1&hash=0.0&hasplugin=3.0.23&requestsrc=android',
                              cookies={'PHPSESSID': session.id})

    if response.status_code != requests.codes.ok:
        raise NetworkError()

    return blob.Blob(decode_blob(response.content), session.key_iteration_count)


def request_iteration_count(username, web_client=http):
    response = web_client.get(f'{default_url}/iterations.php',
                              params={'email': username},
                              headers=headers)
    if response.status_code != requests.codes.ok:
        raise NetworkError()

    try:
        count = int(response.content)
    except:
        raise InvalidResponseError('Key iteration count is invalid')

    if count > 0:
        return count
    raise InvalidResponseError('Key iteration count is not positive')


def request_login(username, password, key_iteration_count, multifactor_password=None, client_id=None, web_client=http, url=default_url):
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

    response = web_client.post(f'{url}/login.php',
                               data=body,
                               headers=headers)

    if response.status_code != requests.codes.ok:
        raise NetworkError()

    try:
        parsed_response = etree.fromstring(response.content)
    except etree.ParseError:
        parsed_response = None

    if parsed_response is None:
        raise InvalidResponseError()

    # Handle lastpass.eu and future other accounts
    new_url = check_lastpass_url(parsed_response)

    if new_url is not None:
        return request_login(username, password, key_iteration_count, multifactor_password, client_id, web_client, url=new_url)

    session = create_session(parsed_response, key_iteration_count, url)
    if not session:
        raise login_error(parsed_response)
    return session

def create_session(parsed_response, key_iteration_count, url):
    if parsed_response.tag == 'ok':
        session_id = parsed_response.attrib.get('sessionid')
        if isinstance(session_id, str):
            return Session(session_id, key_iteration_count, url)

def check_lastpass_url(parsed_response):
    error = None if parsed_response.tag != 'response' else parsed_response.find('error')
    
    if error is None or len(error.attrib) == 0:
        return None

    if error.attrib.get('server') is not None and error.attrib.get('server') != default_url:
        return f"https://{error.attrib.get('server')}"
    
    return None

def login_error(parsed_response):
    error = None if parsed_response.tag != 'response' else parsed_response.find('error')
    if error is None or len(error.attrib) == 0:
        raise UnknownResponseSchemaError()
    
    exceptions = {
        "user_not_exists": LastPassUnknownUsernameError,
        "password_invalid": LastPassInvalidPasswordError,
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
        return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), username.encode('utf-8'), key_iteration_count, 32)


def make_hash(username, password, key_iteration_count):
    # type: (str, str, int) -> bytes
    if key_iteration_count == 1:
        return bytearray(hashlib.sha256(hexlify(make_key(username, password, 1)) + password.encode('utf-8')).hexdigest(), 'ascii')
    else:
        return hexlify(hashlib.pbkdf2_hmac(
            'sha256',
            make_key(username, password, key_iteration_count),
            password.encode('utf-8'),
            1,
            32
        ))
