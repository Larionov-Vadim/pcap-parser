# coding: utf-8

__author__ = 'vadim'

def formatting(mac_address):
    return "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" %\
           (ord(mac_address[0]), ord(mac_address[1]),
            ord(mac_address[2]), ord(mac_address[3]),
            ord(mac_address[4]), ord(mac_address[5]))

def hex_print(s):
    for c in s:
        print(format(ord(c), 'x')),
    print
