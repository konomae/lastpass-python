# coding: utf-8
class Account(object):
    def __init__(self, id, name, username, password, url, group):
        self.id = id
        self.name = name
        self.username = username
        self.password = password
        self.url = url
        self.group = group
        self.accountinfo = [self.group, self.id, self.name, self.username, self.password, self.url]

    def __str__(self):
        _mystring = ''
        for e in self.accountinfo:
            _mystring = _mystring + str(e) + ' '
        return _mystring[:-1]
