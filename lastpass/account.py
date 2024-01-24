# coding: utf-8
import types


class Account(object):
    """
    Lastpass Password Account
    """
    def __init__(self, _id, name, username, password, url, group, notes=None):
        self.id = _id
        self.name = name
        self.username = username
        self.password = password
        self.url = url
        self.group = group
        self.notes = notes

    def notes_string(self):
        if type(self.notes) == bytes:
            note_str = '{}'.format(self.notes.decode())
        else:
            note_str = '{}'.format(str(self.notes))
        return note_str

    def fields(self):
        result_fields = []
        for field in dir(self):
            if not field.startswith('_') and not callable(getattr(self, field)):
                result_fields.append(field)
        return result_fields

    def __str__(self):
        return "name: {}\n\tusername: {}\n\tpassword: {}\n\turl: {}\n\tgroup: {}\n\tnotes: {}".format(self.name, self.username, self.password, self.url, self.group, self.notes_string())


class SecureNote(Account):
    """
    Lastpass Secure Note
    """
    def __init__(self):
        pass

    def __str__(self):
        try:
            return getattr(self, 'unparsed_notes_0').decode()
        except AttributeError:
            return '\n'.join(['\t\t{}: {}'.format(field, getattr(self, field).decode()) for field in self.fields()])
