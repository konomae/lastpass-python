# coding: utf-8
import hashlib
import random
import string
from base64 import b64decode
from binascii import hexlify
from xml.etree import ElementTree as etree
import requests

from . import blob
from .exceptions import (
    NetworkError,
    InvalidResponseError,
    UnknownResponseSchemaError,
    LastPassUnknownUsernameError,
    LastPassInvalidPasswordError,
    LastPassIncorrectGoogleAuthenticatorCodeError,
    LastPassIncorrectYubikeyPasswordError,
    LastPassIncorrectOutOfBandRequiredError,
    LastPassIncorrectMultiFactorResponseError,
    LastPassUnknownError
)
from .session import Session


http = requests


def login(username, password, multifactor_password=None, client_id=None, trust_id=None, trust_me=False):
    key_iteration_count = request_iteration_count(username)
    return request_login(username, password, key_iteration_count, multifactor_password, client_id, trust_id=trust_id, trust_me=trust_me)


def logout(session, web_client=http):
    # type: (Session, requests) -> None
    response = web_client.get(
        'https://lastpass.com/logout.php?mobile=1',
        cookies={'PHPSESSID': session.id}
    )

    if response.status_code != requests.codes.ok:
        raise NetworkError()


def fetch(session, web_client=http):
    response = web_client.get('https://lastpass.com/getaccts.php?mobile=1&b64=1&hash=0.0&hasplugin=3.0.23&requestsrc=android',
                              cookies={'PHPSESSID': session.id})

    if response.status_code != requests.codes.ok:
        raise NetworkError()

    return blob.Blob(decode_blob(response.content), session.key_iteration_count)


def request_iteration_count(username, web_client=http):
    response = web_client.post('https://lastpass.com/iterations.php',
                               data={'email': username})
    if response.status_code != requests.codes.ok:
        raise NetworkError()

    try:
        count = int(response.content)
    except Exception:
        raise InvalidResponseError('Key iteration count is invalid')

    if count > 0:
        return count
    raise InvalidResponseError('Key iteration count is not positive')


def request_login(username, password, key_iteration_count, multifactor_password=None, client_id=None, web_client=http, trust_id=None, trust_me=False):
    body = {
        'method': 'cli',
        'xml': 2,
        'username': username,
        'hash': make_hash(username, password, key_iteration_count),
        'iterations': key_iteration_count,
        'includeprivatekeyenc': 1,
        'outofbandsupported': 1
    }

    if multifactor_password:
        body['otp'] = multifactor_password

    if trust_me and not trust_id:
        trust_id = generate_trust_id()

    if trust_id:
        body['uuid'] = trust_id

    if client_id:
        body['trustlabel'] = client_id

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

    session = create_session(parsed_response, key_iteration_count, trust_id)
    if not session:
        try:
            raise login_error(parsed_response)
        except LastPassIncorrectOutOfBandRequiredError:
            (session, parsed_response) = oob_login(web_client, parsed_response, body, key_iteration_count, trust_id)
            if not session:
                raise login_error(parsed_response)
    if trust_me:
        response = web_client.post('https://lastpass.com/trust.php', cookies={'PHPSESSID': session.id}, data={"token": session.token, "uuid": trust_id, "trustlabel": client_id})

    return session


def oob_login(web_client, parsed_response, body, key_iteration_count, trust_id):
    error = None if parsed_response.tag != 'response' else parsed_response.find(
        'error')
    if 'outofbandname' not in error.attrib or 'capabilities' not in error.attrib:
        return (None, parsed_response)
    oob_capabilities = error.attrib['capabilities'].split(',')
    can_do_passcode = 'passcode' in oob_capabilities
    if can_do_passcode and 'outofband' not in oob_capabilities:
        return (None, parsed_response)
    body['outofbandrequest'] = '1'
    retries = 0
    # loop waiting for out of band approval, or failure
    while retries < 5:
        retries += 1
        response = web_client.post("https://lastpass.com/login.php", data=body)
        if response.status_code != requests.codes.ok:
            raise NetworkError()

        try:
            parsed_response = etree.fromstring(response.content)
        except etree.ParseError:
            parsed_response = None

        if parsed_response is None:
            raise InvalidResponseError()

        session = create_session(parsed_response, key_iteration_count, trust_id)
        if session:
            return (session, parsed_response)
        error = None if parsed_response.tag != 'response' else parsed_response.find(
            'error')
        if 'cause' in error.attrib and error.attrib['cause'] == 'outofbandrequired':
            if 'retryid' in error.attrib:
                body['outofbandretryid'] = error.attrib['retryid']
            body['outofbandretry'] = "1"
            continue
        return (None, parsed_response)
    return (None, parsed_response)


def generate_trust_id():
    return ''.join(random.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase + "!@#$") for _ in range(32))


def create_session(parsed_response, key_iteration_count, trust_id):
    if parsed_response.tag == 'ok':
        ok_response = parsed_response
    else:
        ok_response = parsed_response.find("ok")
    if ok_response is not None:
        session_id = ok_response.attrib.get('sessionid')
        token = ok_response.attrib.get('token')
        if isinstance(session_id, str):
            return Session(session_id, key_iteration_count, token, trust_id)
    return None


def login_error(parsed_response):
    error = None if parsed_response.tag != 'response' else parsed_response.find('error')
    if error is None or not error.attrib:
        raise UnknownResponseSchemaError()

    exceptions = {
        "unknownemail": LastPassUnknownUsernameError,
        "unknownpassword": LastPassInvalidPasswordError,
        "googleauthrequired": LastPassIncorrectGoogleAuthenticatorCodeError,
        "googleauthfailed": LastPassIncorrectGoogleAuthenticatorCodeError,
        "yubikeyrestricted": LastPassIncorrectYubikeyPasswordError,
        "outofbandrequired": LastPassIncorrectOutOfBandRequiredError,
        "multifactorresponsefailed": LastPassIncorrectMultiFactorResponseError,
    }

    cause = error.attrib.get('cause')
    message = error.attrib.get('message')

    if cause:
        return exceptions.get(cause, LastPassUnknownError)(message or cause)
    return InvalidResponseError(message)


def decode_blob(blob_):
    return b64decode(blob_)


def make_key(username, password, key_iteration_count):
    # type: (str, str, int) -> bytes
    if key_iteration_count == 1:
        return hashlib.sha256(username.encode('utf-8') + password.encode('utf-8')).digest()
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), username.encode('utf-8'), key_iteration_count, 32)


def make_hash(username, password, key_iteration_count):
    # type: (str, str, int) -> bytes
    if key_iteration_count == 1:
        return bytearray(hashlib.sha256(hexlify(make_key(username, password, 1)) + password.encode('utf-8')).hexdigest(), 'ascii')
    return hexlify(hashlib.pbkdf2_hmac(
        'sha256',
        make_key(username, password, key_iteration_count),
        password.encode('utf-8'),
        1,
        32
    ))
