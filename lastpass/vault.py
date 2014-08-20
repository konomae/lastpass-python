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
        for i in Parser.extract_chunks(blob):
            if i.id == b'ACCT':
                self.accounts.append(Parser.parse_account(i, encryption_key))
            elif i.id == b'SHAR':
                # We need to stop at the first shared folder chunk
                # All account below are encrypted with different keys
                # Not supported at the moment
                break
