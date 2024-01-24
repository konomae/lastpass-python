# coding: utf-8
class Chunk(object):
    def __init__(self, id_, payload):
        self.id = id_
        self.payload = payload

    def __eq__(self, other):
        return self.id == other.id and self.payload == other.payload
