#!/usr/bin/env python
# coding: utf-8
from __future__ import print_function

import json
import os
from lastpass import (
    Vault,
    LastPassIncorrectYubikeyPasswordError,
    LastPassIncorrectGoogleAuthenticatorCodeError
)

DEVICE_ID = "example.py"


with open(os.path.join(os.path.dirname(__file__), 'credentials.json')) as f:
    credentials = json.load(f)
    username = credentials['username']
    password = credentials['password']

try:
    # First try without a multifactor password
    vault = Vault.open_remote(username, password, None, DEVICE_ID)
except LastPassIncorrectGoogleAuthenticatorCodeError as e:
    # Get the code
    multifactor_password = input('Enter Google Authenticator code:')

    # And now retry with the code
    vault = Vault.open_remote(username, password, multifactor_password, DEVICE_ID)
except LastPassIncorrectYubikeyPasswordError as e:
    # Get the code
    multifactor_password = input('Enter Yubikey password:')

    # And now retry with the code
    vault = Vault.open_remote(username, password, multifactor_password, DEVICE_ID)


for index, i in enumerate(vault.accounts):
    print("{} {} {} {} {} {} {} {}".format(index + 1, i.id, i.name, i.username, i.password, i.url, i.group, i.notes))
