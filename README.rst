LastPass Python API
===================

.. image:: https://travis-ci.org/konomae/lastpass-python.svg?branch=master
  :target: https://travis-ci.org/konomae/lastpass-python

.. image:: https://codecov.io/gh/konomae/lastpass-python/branch/master/graph/badge.svg
  :target: https://codecov.io/gh/konomae/lastpass-python

:Original: `lastpass-ruby <https://github.com/detunized/lastpass-ruby>`_

**This is unofficial LastPass API**


Install
-------

.. code-block:: bash

    $ pip install lastpass-python


Example
-------

.. code-block:: python

    # coding: utf-8
    import lastpass

    vault = lastpass.Vault.open_remote(username, password)
    for i in vault.accounts:
        print(i.id, i.username, i.password, i.url)



Testing
-------

Install test dependencies

.. code-block:: bash

    $ pip install -r requirements.txt

Run tests with

.. code-block:: bash

    $ nosetests

or test all environments and pep8 with tox

.. code-block:: bash

    $ tox



License
-------

`The MIT License <https://opensource.org/licenses/mit-license.php>`_

