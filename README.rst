LastPass Python API
===================

:Original: `lastpass-ruby <https://github.com/detunized/lastpass-ruby>`_

**This is unofficial LastPass API**

Example
-------

::

    # coding: utf-8
    from lastpass import Fetcher, Parser

    fetcher = Fetcher.fetch('username', 'password')
    parser = Parser.parse(fetcher.blob, fetcher.encryption_key)
    accounts = parser.chunks['ACCT']
    print accounts


License
-------

`The MIT License <http://opensource.org/licenses/mit-license.php>`_

