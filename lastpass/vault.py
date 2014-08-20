# coding: utf-8
from .fetcher import Fetcher
from .parser import Parser


class Vault(object):
    # Fetches a blob from the server and creates a vault
    @classmethod
    def open_remote(cls, username, password, multifactor_password=None):
        return cls.open(cls.fetch_blob(username, password, multifactor_password), username, password)

    # Creates a vault from a locally stored blob
    @classmethod
    def open_local(cls, blob_filename, username, password):
        # TODO: read the blob here
        pass

    # Creates a vault from a blob object
    @classmethod
    def open(cls, blob, username, password):
        return cls(blob, blob.encryption_key(username, password))

    # Just fetches the blob, could be used to store it locally
    @classmethod
    def fetch_blob(cls, username, password, multifactor_password=None):
        return Fetcher.fetch(Fetcher.login(username, password, multifactor_password))

    # This more of an internal method, use one of the static constructors instead
    def __init__(self, blob, encryption_key):
        self.accounts = []
        key = encryption_key
        for i in Parser.extract_chunks(blob):
            if i.id == b'ACCT':
                self.accounts.append(Parser.parse_ACCT(i, key))
            elif i.id == b'PRIK':
                rsa_private_key = Parser.parse_PRIK(i, encryption_key)
            elif i.id == b'SHAR':
                # After SHAR chunk all the folliwing accounts are enrypted with a new key
                key = Parser.parse_SHAR(i, encryption_key)['key']
