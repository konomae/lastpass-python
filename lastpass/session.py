# coding: utf-8
class Session(object):
    def __init__(self, id, key_iteration_count, csrf_token=None):
        self.id = id
        self.key_iteration_count = key_iteration_count
        self.csrf_token = csrf_token

    def __eq__(self, other):
        return self.id == other.id and self.key_iteration_count == other.key_iteration_count and self.csrf_token == other.csrf_token
