# coding: utf-8
import os

__author__ = 'vadim'

def formatting(mac_address):
    """
    Форматирует вывод MAC-адреса
    :param mac_address: MAC-адрес
    :return: строка в виде форматированного MAC-адреса
    """
    return "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" %\
           (ord(mac_address[0]), ord(mac_address[1]),
            ord(mac_address[2]), ord(mac_address[3]),
            ord(mac_address[4]), ord(mac_address[5]))

def hex_print(s):
    """
    Печать символов строки s в виде ASCII-символов
    :param s: строка
    :return:
    """
    for c in s:
        print(format(ord(c), 'x')),
    print

def create_path_name(*args):
    """
    Создания пути к каталогу или файлу
    :param args: кортеж аргументов для конкатенации
    :return: строка в виде пути к файлу или каталогу
    """
    path = str()
    for arg in args:
        path += arg
        path += '/'
    if path.endswith('/'):
        path = path[:-1]
    return path


def create_dir(directory):
    """
    Создание каталога, если такой не существует
    :param directory: имя/путь директории
    :return:
    """
    if not os.path.exists(directory):
        os.makedirs(directory)
