# coding: utf-8
import json
import os
import lastpass

with open(os.path.join(os.path.dirname(__file__), 'credentials.json')) as f:
    credentials = json.load(f)
    username = str(credentials['username'])
    password = str(credentials['password'])

try:
    # First try without a multifactor password
    vault = lastpass.Vault.open_remote(username, password)
except lastpass.LastPassIncorrectGoogleAuthenticatorCodeError as e:
    # Get the code
    multifactor_password = input('Enter Google Authenticator code:')

    # And now retry with the code
    vault = lastpass.Vault.open_remote(username, password, multifactor_password)
except lastpass.LastPassIncorrectYubikeyPasswordError as e:
    # Get the code
    multifactor_password = input('Enter Yubikey password:')

    # And now retry with the code
    vault = lastpass.Vault.open_remote(username, password, multifactor_password)


for index, i in enumerate(vault.accounts):
    print("{} {} {} {} {} {} {}".format(index + 1, i.id, i.name, i.username, i.password, i.url, i.group))
