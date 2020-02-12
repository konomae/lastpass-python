# coding: utf-8
class Session(object):
    def __init__(self, id, key_iteration_count, token=None, trust_id=None):
        self.id = id
        self.key_iteration_count = key_iteration_count
        self.token = token
        self.trust_id = trust_id

    def __eq__(self, other):
        return self.id == other.id and self.key_iteration_count == other.key_iteration_count and self.token == other.token
