# coding: utf-8
from StringIO import StringIO
import struct

from Crypto.Cipher import AES


class Parser(object):
    @classmethod
    def parse(cls, blob, encryption_key):
        parser = cls(blob, encryption_key)
        parser._parse()

        return parser

    def __init__(self, blob, encryption_key):
        self.blob = blob
        self.encryption_key = encryption_key

    def _parse(self):
        self.chunks = self._parse_chunks(self._extract_chunks(self._decode_blob(self.blob)))

    def _decode_blob(self, blob):
        if not isinstance(blob, basestring):
            raise ValueError('Blob should be a string')

        if not blob.startswith('TFBB'):
            raise ValueError("Blob doesn't seem to be base64 encoded")

        return blob.decode('base64')

    def _extract_chunks(self, blob):
        chunks = {}
        stream = StringIO(blob)
        while stream.pos < stream.len:
            chunk = self._read_chunk(stream)
            id = chunk['id']
            if not chunks.get(id):
                chunks[id] = []
            chunks[id].append(chunk['payload'])

        return chunks

    def _each_chunk(self, stream):
        while stream.pos < stream.len:
            yield self._read_chunk(stream)

    def _parse_chunks(self, raw_chunk):
        parsed_chunks = {}
        for id, chunks in raw_chunk.items():
            parse_method = '_parse_chunk_{id}'.format(id=id)
            if hasattr(self, parse_method) and callable(getattr(self, parse_method)):
                parse_method = getattr(self, parse_method)
                parsed_chunks[id] = [parse_method(StringIO(chunk)) for chunk in chunks]

        return parsed_chunks


    def _read_chunk(self, stream):
        id = stream.read(4)
        size = self._read_uint32(stream)
        payload = stream.read(size)

        return {'id': id, 'size': size, 'payload': payload}


    def _read_item(self, stream):
        size = self._read_uint32(stream)
        payload = stream.read(size)

        return {'size': size, 'payload': payload}


    def _read_uint32(self, stream):
        return struct.unpack('>I', stream.read(4))[0]


    def _decode(self, data, encoding=None):
        if not encoding or encoding == 'plain':
            return data
        else:
            decode_method = getattr(self, '_decode_{}'.format(encoding), None)
            if decode_method:
                return decode_method(data)

    def _decode_base64(self, data):
        return data.decode('base64')

    def _decode_hex(self, data):
        return data.decode('hex')

    def _decode_aes256(self, data):
        length = len(data)
        length16 = length % 16
        length64 = length % 64

        if length == 0:
            return ''
        elif length16 == 0:
            return self._decode_aes256_ecb_plain(data)
        elif length64 == 0 or length64 == 24 or length64 == 44:
            return self._decode_aes256_ecb_base64(data)
        elif length16 == 1:
            return self._decode_aes256_cbc_plain(data)
        elif length64 == 6 or length64 == 26 or length64 or 50:
            return self._decode_aes256_cbc_base64(data)
        else:
            raise RuntimeError("'{}' doesn't seem to be AES-256 encrypted".format(repr(data)))

    def _decode_aes256_ecb_plain(self, data):
        if not data:
            return ''
        else:
            return self.__decode_aes256('ecb', '', data)

    def _decode_aes256_ecb_base64(self, data):
        self._decode_aes256_ecb_plain(self._decode_base64(data))

    def _decode_aes256_cbc_plain(self, data):
        if not data:
            return ''
        else:
            return self.__decode_aes256('cbc', data[1:17], data[17:])

    def _decode_aes256_cbc_base64(self, data):
        if not data:
            return ''
        else:
            return self.__decode_aes256(
                'cbc',
                self._decode_base64(data[1:25]),
                self._decode_base64(data[26:]))

    def __decode_aes256(self, cipher, iv, data):
        if cipher == 'cbc':
            aes_mode = AES.MODE_CBC
        elif cipher == 'ecb':
            aes_mode = AES.MODE_ECB
        else:
            raise ValueError('Unknown AES mode')
        aes = AES.new(self.encryption_key, aes_mode, iv)
        d = aes.decrypt(data)
        # http://passingcuriosity.com/2009/aes-encryption-in-python-with-m2crypto/
        unpad = lambda s : s[0:-ord(s[-1])]
        return unpad(d)

    def _parse_itemized_chunk(self, stream, info):
        chunk = {}

        for item_info in info:
            chunk[item_info['name']] = self._parse_item(stream, item_info.get('encoding'))

        return chunk

    def _parse_item(self, stream, encoding=None):
        return self._decode(self._read_item(stream)['payload'], encoding)

    def _parse_chunk_LPAV(self, stream):
        return stream.read()

    def _parse_chunk_ENCU(self, stream):
        return self._decode_aes256(stream.read())

    def _parse_chunk_NMAC(self, stream):
        return stream.read()

    def _parse_chunk_ACCT(self, stream):
        return self._parse_itemized_chunk(stream, [
            {'name': 'id'},
            {'name' :'name','encoding' :'aes256'},
            {'name' :'group','encoding' :'aes256'},
            {'name' :'url','encoding' :'hex'},
            {'name' :'extra'},
            {'name' :'favorite'},
            {'name' :'shared_from_id'},
            {'name' :'username','encoding' :'aes256'},
            {'name' :'password','encoding' :'aes256'},
            {'name' :'password_protected'},
            {'name' :'generated_password'},
            {'name' :'sn'}, # ?
            {'name' :'last_touched'},
            {'name' :'auto_login'},
            {'name' :'never_autofill'},
            {'name' :'realm_data'},
            {'name' :'fiid'}, # ?
            {'name' :'custom_js'},
            {'name' :'submit_id'},
            {'name' :'captcha_id'},
            {'name' :'urid'}, # ?
            {'name' :'basic_authorization'},
            {'name' :'method'},
            {'name' :'action','encoding' :'hex'},
            {'name' :'group_id'},
            {'name' :'deleted'},
            {'name' :'attach_key'},
            {'name' :'attach_present'},
            {'name' :'individual_share'},
            {'name' :'unknown1'}
        ])

    def _parse_chunk_EQDN(self, stream):
        return self._parse_itemized_chunk(stream, [
            {'name': 'id'},
            {'name': 'domain', 'encoding': 'hex'},
        ])
