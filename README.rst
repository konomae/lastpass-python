LastPass Python API
===================

.. image:: https://travis-ci.org/konomae/lastpass-python.png?branch=master
  :target: https://travis-ci.org/konomae/lastpass-python

.. image:: https://coveralls.io/repos/konomae/lastpass-python/badge.png?branch=master
  :target: https://coveralls.io/r/konomae/lastpass-python?branch=master

:Original: `lastpass-ruby <https://github.com/detunized/lastpass-ruby>`_

**This is unofficial LastPass API**

Example
-------

::

    # coding: utf-8
    import lastpass

    vault = lastpass.Vault.open_remote(username, password)
    for i in vault.accounts:
        print(i.id, i.username, i.password, i.url)


License
-------

`The MIT License <http://opensource.org/licenses/mit-license.php>`_

