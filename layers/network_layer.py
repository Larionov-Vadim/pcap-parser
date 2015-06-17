# coding: utf-8

__author__ = 'vadim'

class IPProtocol:
    HEADER_LENGTH = 20                          # Размер заголовка в байтах

    # Коды инкапсулируемых протоколов
    TCP = 6
    UDP = 17

    def __init__(self):
        self.version = None
        self.ihl = None                         # Размер заголовка (Internet Header Length) в 32-х словах
        self.differentiated_services = None     # Differentiated Services Code Point + Explicit Congestion Notification
        self.packet_size = None                 # Полный размер пакета (заголовок + данные)
        self.id = None                          # Идентификатор
        self.flags = None
        self.offset = None                      # Смещение (13 бит)
        self.ttl = None                         # Time To Live
        self.protocol = None                    # Инкапсулируемый протокол
        self.checksum = None                    # Контрольная сумма заголовка
        self.src_ip = None                      # IP-адрес отправителя
        self.dst_ip = None                      # IP-адрес получателя
        self.data = None
