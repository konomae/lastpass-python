# coding: utf-8
from . import fetcher
from . import parser
from .exceptions import InvalidResponseError


class Vault(object):
    """
    Lastpass Vault
    """
    @classmethod
    def open_remote(cls, username, password, multifactor_password=None, client_id=None, trust_id=None, trust_me=False, blob_filename=None):
        """Fetches a blob from the server and creates a vault"""
        (blob, trust_id) = cls.fetch_blob(username, password, multifactor_password, client_id, trust_id, trust_me, blob_filename)
        return cls.open(blob, username, password, trust_id)

    @classmethod
    def open_local(cls, blob_filename, username, password):
        """Creates a vault from a locally stored blob"""
        blob = cls.read_blob_local(username, password, blob_filename)
        return cls.open(blob, username, password)

    @classmethod
    def open(cls, blob, username, password, trust_id=None):
        """Creates a vault from a blob object"""
        return cls(blob, blob.encryption_key(username, password), trust_id)

    @classmethod
    def fetch_blob(cls, username, password, multifactor_password=None, client_id=None, trust_id=None, trust_me=False, blob_filename=None):
        """Just fetches the blob, could be used to store it locally"""
        session = fetcher.login(username, password, multifactor_password, client_id, trust_id=trust_id, trust_me=trust_me)
        blob = fetcher.fetch(session)
        fetcher.logout(session)
        if blob_filename:
            cls.write_blob_local(blob, username, password, blob_filename)

        return (blob, session.trust_id)

    @classmethod
    def read_blob_local(cls, username, password, blob_filename):
        """Read and decode a blob from a local file """
        with open(blob_filename, 'r') as fp:
            file_data = fp.read().replace('\n', '').strip()
        username_read = file_data[4:104].strip()
        assert username == username_read
        key_iteration_count = 10
        decoding_key = fetcher.make_key(username, password, key_iteration_count)
        inner_decoded = parser.decode_aes256_cbc_base64(file_data[105:], decoding_key)
        key_iteration_count = int(inner_decoded[1:17])
        decoding_key = fetcher.make_key(username, password, key_iteration_count)
        decoded = parser.decompress(parser.decode_aes256_cbc_base64(inner_decoded[17:], decoding_key))
        blob = fetcher.blob.Blob(decoded, key_iteration_count)
        return blob

    @classmethod
    def write_blob_local(cls, blob, username, password, blob_filename):
        """write a blob to a local file"""
        key = fetcher.make_key(username, password, blob.key_iteration_count)
        iv = b"\x00" + parser.random(14) + b"\x00"
        inner_encoded = "#" + "%16d" % blob.key_iteration_count + parser.encode_aes256_cbc_base64(parser.compress(blob.bytes), key, iv).decode()
        iv = b"\x00" + parser.random(14) + b"\x00"
        key_iteration_count = 10
        key = fetcher.make_key(username, password, key_iteration_count)
        file_data = "BLOB" + "%100s" % username + "#" + parser.encode_aes256_cbc_base64(inner_encoded, key, iv).decode()
        with open(blob_filename, 'w') as fp:
            fp.write(file_data)

    def __init__(self, blob, encryption_key, trust_id=None):
        """This more of an internal method, use one of the static constructors instead"""
        chunks = parser.extract_chunks(blob)

        if not self.is_complete(chunks):
            raise InvalidResponseError('Blob is truncated')

        self.accounts = self.parse_accounts(chunks, encryption_key)
        self.trust_id = trust_id

    @classmethod
    def is_complete(self, chunks):
        "Is Chunk Complete"
        return len(chunks) > 0 and chunks[-1].id == b'ENDM' and chunks[-1].payload == b'OK'

    @classmethod
    def parse_accounts(self, chunks, encryption_key):
        "Parse Account"
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
