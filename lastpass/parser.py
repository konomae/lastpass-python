# coding: utf-8
from base64 import b64decode
import binascii
import codecs
from io import BytesIO
import struct
import re

from Crypto.Cipher import AES
from Crypto.Util import number
from Crypto.PublicKey import RSA

from .account import Account
from .chunk import Chunk


class Parser(object):
    # OpenSSL constant
    RSA_PKCS1_OAEP_PADDING = 4

    # Secure note types that contain account-like information
    ALLOWED_SECURE_NOTE_TYPES = [
        b"Server",
        b"Email Account",
        b"Database",
        b"Instant Messenger",
    ]

    # Splits the blob into chucks grouped by kind.
    @classmethod
    def extract_chunks(cls, blob):
        chunks = []
        stream = BytesIO(blob.bytes)
        current_pos = stream.tell()
        stream.seek(0, 2)
        length = stream.tell()
        stream.seek(current_pos, 0)
        while stream.tell() < length:
            chunks.append(cls.read_chunk(stream))

        return chunks

    # Parses an account chunk, decrypts and creates an Account object.
    # May return nil when the chunk does not represent an account.
    # All secure notes are ACCTs but not all of them strore account
    # information.
    #
    # TODO: Make a test case that covers secure note account
    @classmethod
    def parse_ACCT(cls, chunk, encryption_key):
        io = BytesIO(chunk.payload)
        id = cls.read_item(io)
        name = cls.decode_aes256_auto(cls.read_item(io), encryption_key)
        group = cls.decode_aes256_auto(cls.read_item(io), encryption_key)
        url = cls.decode_hex(cls.read_item(io))
        notes = cls.decode_aes256_auto(cls.read_item(io), encryption_key)
        for _ in range(2):
            cls.skip_item(io)
        username = cls.decode_aes256_auto(cls.read_item(io), encryption_key)
        password = cls.decode_aes256_auto(cls.read_item(io), encryption_key)
        for _ in range(2):
            cls.skip_item(io)
        secure_note = cls.read_item(io)

        # Parse secure note
        if secure_note == b"1":
            for _ in range(17):
                cls.skip_item(io)
            secure_note_type = cls.read_item(io)

            # Only "Server" secure note stores account information
            if secure_note_type not in cls.ALLOWED_SECURE_NOTE_TYPES:
                return None

            url, username, password = cls.parse_secure_note_server(notes)

        return Account(id, name, username, password, url, group)

    @classmethod
    def parse_PRIK(cls, chunk, encryption_key):
        decrypted = cls.decode_aes256('cbc',
                                      encryption_key[:16],
                                      cls.decode_hex(chunk.payload),
                                      encryption_key)

        hex_key = re.match(br'^LastPassPrivateKey<(?P<hex_key>.*)>LastPassPrivateKey$', decrypted).group('hex_key')
        rsa_key = RSA.importKey(cls.decode_hex(hex_key))

        rsa_key.dmp1 = rsa_key.d % (rsa_key.p - 1)
        rsa_key.dmq1 = rsa_key.d % (rsa_key.q - 1)
        rsa_key.iqmp = number.inverse(rsa_key.q, rsa_key.p)

        return rsa_key

    @classmethod
    def parse_SHAR(cls, chunk, encryption_key, rsa_key):
        io = BytesIO(chunk.payload)
        id = cls.read_item(io)
        encrypted_key = cls.decode_hex(cls.read_item(io))
        encrypted_name = cls.read_item(io)
        for _ in range(2):
            cls.skip_item(io)
        key = cls.read_item(io)

        # Shared folder encryption key might come already in pre-decrypted form,
        # where it's only AES encrypted with the regular encryption key.
        # When the key is blank, then there's a RSA encrypted key, which has to
        # be decrypted first before use.
        if not key:
            # TODO: rsa_key.private_decrypt(encrypted_key, RSA_PKCS1_OAEP_PADDING)
            key = cls.decode_hex(rsa_key.decrypt(encrypted_key))
        else:
            key = cls.decode_hex(cls.decode_aes256_auto(key, encryption_key))

        name = cls.decode_aes256_auto(encrypted_name, key)

        # TODO: Return an object, not a dict
        return {'id': id, 'name': name, 'encryption_key': key}

    @classmethod
    def parse_secure_note_server(cls, notes):
        url = None
        username = None
        password = None

        for i in notes.split(b'\n'):
            if not i:  # blank line
                continue
            key, value = i.split(b':')
            if key == b'Hostname':
                url = value
            elif key == b'Username':
                username = value
            elif key == b'Password':
                password = value

        return [url, username, password]

    # Reads one chunk from a stream and creates a Chunk object with the data read.
    @classmethod
    def read_chunk(cls, stream):
        # LastPass blob chunk is made up of 4-byte ID,
        # big endian 4-byte size and payload of that size.
        #
        # Example:
        #   0000: "IDID"
        #   0004: 4
        #   0008: 0xDE 0xAD 0xBE 0xEF
        #   000C: --- Next chunk ---
        return Chunk(cls.read_id(stream), cls.read_payload(stream, cls.read_size(stream)))

    # Reads an item from a stream and returns it as a string of bytes.
    @classmethod
    def read_item(cls, stream):
        # An item in an itemized chunk is made up of the
        # big endian size and the payload of that size.
        #
        # Example:
        #   0000: 4
        #   0004: 0xDE 0xAD 0xBE 0xEF
        #   0008: --- Next item ---
        return cls.read_payload(stream, cls.read_size(stream))

    # Skips an item in a stream.
    @classmethod
    def skip_item(cls, stream):
        cls.read_item(stream)

    # Reads a chunk ID from a stream.
    @classmethod
    def read_id(cls, stream):
        return stream.read(4)

    # Reads a chunk or an item ID.
    @classmethod
    def read_size(cls, stream):
        return cls.read_uint32(stream)

    # Reads a payload of a given size from a stream.
    @classmethod
    def read_payload(cls, stream, size):
        return stream.read(size)

    # Reads an unsigned 32 bit integer from a stream.
    @classmethod
    def read_uint32(cls, stream):
        return struct.unpack('>I', stream.read(4))[0]

    # Decodes a hex encoded string into raw bytes.
    @classmethod
    def decode_hex(cls, data):
        try:
            return codecs.decode(data, 'hex_codec')
        except binascii.Error:
            raise TypeError()

    # Decodes a base64 encoded string into raw bytes.
    @classmethod
    def decode_base64(cls, data):
        return b64decode(data)

    # Guesses AES encoding/cipher from the length of the data.
    # Possible combinations are:
    #   - ciphers: AES-256 EBC, AES-256 CBC
    #   - encodings: plain, base64
    @classmethod
    def decode_aes256_auto(cls, data, encryption_key):
        length = len(data)
        length16 = length % 16
        length64 = length % 64

        if length == 0:
            return b''
        elif length16 == 0:
            return cls.decode_aes256_ecb_plain(data, encryption_key)
        elif length64 == 0 or length64 == 24 or length64 == 44:
            return cls.decode_aes256_ecb_base64(data, encryption_key)
        elif length16 == 1:
            return cls.decode_aes256_cbc_plain(data, encryption_key)
        elif length64 == 6 or length64 == 26 or length64 == 50:
            return cls.decode_aes256_cbc_base64(data, encryption_key)
        else:
            raise RuntimeError("'{}' doesn't seem to be AES-256 encrypted".format(repr(data)))

    # Decrypts AES-256 ECB bytes.
    @classmethod
    def decode_aes256_ecb_plain(cls, data, encryption_key):
        if not data:
            return b''
        else:
            return cls.decode_aes256('ecb', '', data, encryption_key)

    # Decrypts base64 encoded AES-256 ECB bytes.
    @classmethod
    def decode_aes256_ecb_base64(cls, data, encryption_key):
        return cls.decode_aes256_ecb_plain(cls.decode_base64(data), encryption_key)

    # Decrypts AES-256 CBC bytes.
    @classmethod
    def decode_aes256_cbc_plain(cls, data, encryption_key):
        if not data:
            return b''
        else:
            # LastPass AES-256/CBC encryted string starts with an "!".
            # Next 16 bytes are the IV for the cipher.
            # And the rest is the encrypted payload.
            return cls.decode_aes256('cbc', data[1:17], data[17:], encryption_key)

    # Decrypts base64 encoded AES-256 CBC bytes.
    @classmethod
    def decode_aes256_cbc_base64(cls, data, encryption_key):
        if not data:
            return b''
        else:
            # LastPass AES-256/CBC/base64 encryted string starts with an "!".
            # Next 24 bytes are the base64 encoded IV for the cipher.
            # Then comes the "|".
            # And the rest is the base64 encoded encrypted payload.
            return cls.decode_aes256(
                'cbc',
                cls.decode_base64(data[1:25]),
                cls.decode_base64(data[26:]),
                encryption_key)

    # Decrypt AES-256 bytes.
    # Allowed ciphers are: :ecb, :cbc.
    # If for :ecb iv is not used and should be set to "".
    @classmethod
    def decode_aes256(cls, cipher, iv, data, encryption_key):
        if cipher == 'cbc':
            aes_mode = AES.MODE_CBC
        elif cipher == 'ecb':
            aes_mode = AES.MODE_ECB
        else:
            raise ValueError('Unknown AES mode')
        aes = AES.new(encryption_key, aes_mode, iv)
        d = aes.decrypt(data)
        # http://passingcuriosity.com/2009/aes-encryption-in-python-with-m2crypto/
        unpad = lambda s: s[0:-ord(d[-1:])]
        return unpad(d)
