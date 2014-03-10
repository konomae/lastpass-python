# coding: utf-8
from base64 import b64decode
import binascii
import codecs
from io import BytesIO
from collections import OrderedDict
import struct

from Crypto.Cipher import AES
from .account import Account
from .chunk import Chunk


class Parser(object):
    # Splits the blob into chucks grouped by kind.
    @classmethod
    def extract_chunks(cls, blob):
        chunks = OrderedDict()
        stream = BytesIO(blob.bytes)
        current_pos = stream.tell()
        stream.seek(0, 2)
        length = stream.tell()
        stream.seek(current_pos, 0)
        while stream.tell() < length:
            chunk = cls.read_chunk(stream)
            if not chunks.get(chunk.id):
                chunks[chunk.id] = []
            chunks[chunk.id].append(chunk)

        return chunks

    # Parses an account chunk, decrypts and creates an Account object.
    # TODO: See if this should be part of Account class.
    @classmethod
    def parse_account(cls, chunk, encryption_key):
        io = BytesIO(chunk.payload)
        id = cls.read_item(io)
        name = cls.decode_aes256_auto(cls.read_item(io), encryption_key)
        group = cls.decode_aes256_auto(cls.read_item(io), encryption_key)
        url = cls.decode_hex(cls.read_item(io))
        for _ in range(3):
            cls.skip_item(io)
        username = cls.decode_aes256_auto(cls.read_item(io), encryption_key)
        password = cls.decode_aes256_auto(cls.read_item(io), encryption_key)

        return Account(id, name, username, password, url, group)

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
