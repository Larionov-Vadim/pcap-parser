# coding: utf-8
import socket
from struct import unpack

from layers.data_link_layer import EthernetII
from layers.network_layer import IPProtocol
from layers.transport_layer import TCPProtocol

__author__ = 'vadim'

class PcapParser:
    def __init__(self):
        pass

    def parse(self, frame):
        """
        Производит разбор (парсит) кадра канального уровня на известные протоколы.
        Известные протоколы:
            * Канальный уровень: Ethernet II
            * Сетевой уровень: IPv4
            * Транспортный уровень: TCP
            * Прикладной уровень:
        :param frame: кадр канального уровня в виде байт
        :return:
        """
        ethernet_frame = self.parse_frame(frame)
        if ethernet_frame.ether_type == 8:              # IP-пакет
            ip_packet = self.parse_ip_packet(ethernet_frame.data)
            ethernet_frame.data = ip_packet
            if ip_packet.protocol == 6:
                tcp_segment = self.parse_tcp_segment(ip_packet.data)
                ip_packet.data = tcp_segment
                if len(tcp_segment.data) != 0:
                    print(tcp_segment.data)

    def parse_frame(self, frame):
        """
        Парсер кадра канального уровня протокола Ethernet II
        :param frame: кадр канального уровня в виде байт
        :return: экземпляр класса EthernetFrame
        """
        # TODO HardCode
        ethernet_length = 14                        # длина заголовка кадра в протоколе Ethernet II
        ethernet_header = frame[:ethernet_length]   # Ethernet заголовок
        eth = unpack('!6s6sH', ethernet_header)     # формирует кортеж согласно параметрам разбора
        ether_type = socket.ntohs(eth[2])           # преобразование из big endian в тип протокола

        ethernet_frame = EthernetII(dst_mac=eth[0], src_mac=eth[1], ether_type=ether_type)
        ethernet_frame.data = frame[ethernet_length:]
        return ethernet_frame

    def parse_ip_packet(self, packet):
        """
        Парсер пакета сетевого уровня протокола IPv4
        :param packet: пакет сетевого уровня протокола IPv4 в виде байт
        :return: экземлпяр класса IpPacket()
        """
        ip_packet = IPProtocol()
        # TODO HardCode
        iph = unpack('!BBHHHBBH4s4s', packet[:20])      # Заголовок IP-пакета без опций

        ip_packet.version = iph[0] >> 4
        ip_packet.ihl = iph[0] & 0xF
        ip_packet.differentiated_services = iph[1]
        ip_packet.packet_size = iph[2]

        # TODO лучше ничего не придумал
        ip_packet.id = iph[3]
        flags_byte = iph[4] >> 8
        ip_packet.flags = (
            bool(flags_byte & 0b10000000),
            bool(flags_byte & 0b01000000),
            bool(flags_byte & 0b00100000),
        )
        ip_packet.offset = (iph[4] & ((0b00011111 << 8) | 0xFF))

        ip_packet.ttl = iph[5]
        ip_packet.protocol = iph[6]
        ip_packet.checksum = iph[7]
        ip_packet.src_ip = socket.inet_ntoa(iph[8])
        ip_packet.dst_ip = socket.inet_ntoa(iph[9])
        # Параметры пропускаются
        ip_packet.data = packet[ip_packet.ihl * 4:]         # TODO Объяснить
        return ip_packet

    def parse_tcp_segment(self, segment):
        """
        Парсер сегмента транспортного уровня протокола TCP
        :param packet: сегмент (дэйтаграмма) транспортного уровня в виде байт
        :return: экземлпяр класса IpPacket()
        """
        tcp_segment = TCPProtocol()
        tcph = unpack('!HHLLBBhHH', segment[:20])

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

        tcp_segment.data = segment[tcp_segment.data_offset * 4:]
        return tcp_segment

    def parse_pop3(self, message):
        # TODO
        pass
