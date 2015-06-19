# coding: utf-8
from struct import unpack

__author__ = 'vadim'

class TCPProtocol:
    HEADER_LENGTH = 20                          # Размер заголовка в байтах

    def __init__(self):
        self.src_port = None                    # Номер порта отправителя
        self.dst_port = None                    # Номер порта получателя
        self.sequence_number = None             # Порядковый номер
        self.acknowledgment_number = None       # Номер подтверждения
        self.data_offset = None                 # Длина заголовка в 4-х байтных словах
        self.reserved = None                    # Зарезервировано
        self.flags = None                       # Флаги
        self.window_size = None                 # Размер окна
        self.checksum = None                    # Контрольная сумма
        self.urgent_pointer = None              # Указатель важности
        self.data = None                        # Инкапсулируемое содержимое

    @staticmethod
    def parse(segment):
        """
        Парсер сегмента транспортного уровня протокола TCP
        :param packet: сегмент (дэйтаграмма) транспортного уровня в виде байт
        :return: экземлпяр класса IpPacket()
        """
        tcp_segment = TCPProtocol()
        tcph = unpack('!HHLLBBhHH', segment[:TCPProtocol.HEADER_LENGTH])

        tcp_segment.src_port = tcph[0]
        tcp_segment.dst_port = tcph[1]
        tcp_segment.sequence_number = tcph[2]
        tcp_segment.acknowledgment_number = tcph[3]

        tcp_segment.data_offset = (tcph[4] & 0xF0) >> 4
        tcp_segment.reserved = (tcph[4] & 0b00001110) >> 1
        tcp_segment.flags = ((tcph[4] & 0x01) << 8) | tcph[5]

        tcp_segment.window_size = tcph[6]
        tcp_segment.checksum = tcph[7]
        tcp_segment.urgent_pointer = tcph[8]

        # Длина заголовка в 4х байтных слова => умножение на 4
        tcp_segment.data = segment[tcp_segment.data_offset * 4:]
        return tcp_segment


class UDPProtocol:
    HEADER_LENGTH = 8

    def __init__(self):
        self.src_port = None                    # Порт отправителя
        self.dst_port = None                    # Порт получателя
        self.length = None                      # Длина всей датаграммы (заголовок + данные)
        self.checksum = None                    # Контрольная сумма
        self.data = None                        # Данные

    def __str__(self):
        return 'Src_port: ' + str(self.src_port) +\
                ' Dst_port: ' + str(self.dst_port) +\
                ' Length: ' + str(self.length) +\
                ' Checksum: ' + str(self.checksum) +\
                ' Data: ' + str(self.data)

    @staticmethod
    def parse(datagram):
        udp_datagram = UDPProtocol()
        udph = unpack('!HHHH', datagram[:UDPProtocol.HEADER_LENGTH])

        udp_datagram.src_port = udph[0]
        udp_datagram.dst_port = udph[1]
        udp_datagram.length = udph[2]
        udp_datagram.checksum = udph[3]
        udp_datagram.data = datagram[UDPProtocol.HEADER_LENGTH:]
        return udp_datagram
