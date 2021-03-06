# coding: utf-8
from struct import unpack
from utils import formatting

__author__ = 'vadim'


class EthernetII:
    HEADER_LENGTH = 14              # Размер заголовка в байтах
    ETHER_TYPE_IPv4 = 0x0800

    def __init__(self, dst_mac=None, src_mac=None, ether_type=None, data=None):
        """
        Кадр канального уровня протокола Ethernet II
        :param dst_mac: MAC-адрес получателя
        :param src_mac: MAC-адрес отправителя
        :param ether_type: тип протокола инкапсулируемого пакета
        :param data: инкапсулированный пакет
        :return:
        """
        self.dst_mac = dst_mac
        self.src_mac = src_mac
        self.ether_type = ether_type
        self.data = data

    def __str__(self):
        return 'Destination MAC : ' + formatting(self.src_mac) + \
               ' Source MAC : ' + formatting(self.dst_mac) + \
               ' Protocol : ' + str(self.ether_type)

    @staticmethod
    def parse(frame):
        """
        Парсер кадра канального уровня протокола Ethernet II
        :param frame: кадр канального уровня в виде байт
        :return: экземпляр класса EthernetFrame
        """
        ethernet_length = EthernetII.HEADER_LENGTH  # Длина заголовка кадра в протоколе Ethernet II
        ethernet_header = frame[:ethernet_length]  # Ethernet заголовок
        eth = unpack('!6s6sH', ethernet_header)  # Формирует кортеж согласно параметрам разбора

        ethernet_frame = EthernetII(dst_mac=eth[0], src_mac=eth[1], ether_type=eth[2])
        ethernet_frame.data = frame[ethernet_length:]
        return ethernet_frame
