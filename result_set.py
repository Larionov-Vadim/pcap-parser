# coding: utf-8
from hashlib import md5

__author__ = 'vadim'

class ResultSet:
    def __init__(self, src_ip, dst_ip, data, file_extension):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.data = data
        self.file_extension = file_extension

    def generate_file_name(self, index=None):
        hash = md5(self.data)
        file_name = hash.hexdigest()
        if index is not None:
            file_name += '_%i' % index
        file_name += self.file_extension
        return file_name
