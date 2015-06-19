# coding: utf-8
import socket
from struct import unpack

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

    @staticmethod
    def parse(packet):
        """
        Парсер пакета сетевого уровня протокола IPv4
        :param packet: пакет сетевого уровня протокола IPv4 в виде байт
        :return: экземлпяр класса IpPacket()
        """
        ip_packet = IPProtocol()
        iph = unpack('!BBHHHBBH4s4s', packet[:IPProtocol.HEADER_LENGTH])  # Заголовок IP-пакета без опций

        ip_packet.version = iph[0] >> 4  # Старшие 4 бита отвечают за версию
        ip_packet.ihl = iph[0] & 0xF  # Младшие 4 бита отвечают за IHL
        ip_packet.differentiated_services = iph[1]
        ip_packet.packet_size = iph[2]

        ip_packet.id = iph[3]
        # Обработка флагов битовыми операциями
        flags_byte = iph[4] >> 8
        ip_packet.flags = {
            'reserved_bit': bool(flags_byte & 0b10000000),  # Reserved, always is 0
            'DF': bool(flags_byte & 0b01000000),            # Don't fragment
            'MF': bool(flags_byte & 0b00100000),            # More fragments
        }
        ip_packet.offset = (iph[4] & ((0b00011111 << 8) | 0xFF))

        ip_packet.ttl = iph[5]
        ip_packet.protocol = iph[6]
        ip_packet.checksum = iph[7]
        ip_packet.src_ip = socket.inet_ntoa(iph[8])
        ip_packet.dst_ip = socket.inet_ntoa(iph[9])
        # Параметры пропускаются

        # IHL - Internet Header Length - размер заголовка в 32х битных словах
        # Данные начинаются с [IHL * 32 / 8] <=> [IHL * 4] (перевод из бит в байты)
        ip_packet.data = packet[ip_packet.ihl * 4:]
        return ip_packet
