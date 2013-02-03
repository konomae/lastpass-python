# coding: utf-8
from lastpass import Fetcher, Parser

fetcher = Fetcher.fetch('username', 'password')
parser = Parser.parse(fetcher.blob, fetcher.encryption_key)
accounts = parser.chunks['ACCT']
print accounts