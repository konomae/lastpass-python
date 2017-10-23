# coding: utf-8
from . import fetcher
from . import parser
from .exceptions import InvalidResponseError


class Vault(object):
    @classmethod
    def open_remote(cls, username, password, multifactor_password=None):
        """Fetches a blob from the server and creates a vault"""
        return cls.open(cls.fetch_blob(username, password, multifactor_password), username, password)

    @classmethod
    def open_local(cls, blob_filename, username, password):
        """Creates a vault from a locally stored blob"""
        # TODO: read the blob here
        pass

    @classmethod
    def open(cls, blob, username, password):
        """Creates a vault from a blob object"""
        return cls(blob, blob.encryption_key(username, password))

    @classmethod
    def fetch_blob(cls, username, password, multifactor_password=None):
        """Just fetches the blob, could be used to store it locally"""
        return fetcher.fetch(fetcher.login(username, password, multifactor_password))

    def __init__(self, blob, encryption_key):
        """This more of an internal method, use one of the static constructors instead"""
        chunks = parser.extract_chunks(blob)

        if not self.is_complete(chunks):
            raise InvalidResponseError('Blob is truncated')

        self.accounts = self.parse_accounts(chunks, encryption_key)

    def is_complete(self, chunks):
        return len(chunks) > 0 and chunks[-1].id == 'ENDM' and chunks[-1].payload == 'OK'

    def parse_accounts(self, chunks, encryption_key):
        accounts = []

        key = encryption_key
        rsa_private_key = None

        for i in chunks:
            if i.id == b'ACCT':
                # TODO: Put shared folder name as group in the account
                account = parser.parse_ACCT(i, key)
                if account:
                    accounts.append(account)
            elif i.id == b'PRIK':
                rsa_private_key = parser.parse_PRIK(i, encryption_key)
            elif i.id == b'SHAR':
                # After SHAR chunk all the folliwing accounts are enrypted with a new key
                key = parser.parse_SHAR(i, encryption_key, rsa_private_key)['encryption_key']

        return accounts
