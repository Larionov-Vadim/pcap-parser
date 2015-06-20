# coding: utf-8
from layers.data_link_layer import EthernetII
from layers.network_layer import IPProtocol
from layers.transport_layer import TCPProtocol, UDPProtocol
from layers.application.pop3 import POP3
from layers.application.dns import DNS
from result_set import ResultSet

__author__ = 'vadim'


class PcapParser:
    """
    Парсер сетевого трафика
    """
    def __init__(self):
        pass

    def parse(self, frame):
        """
        Производит разбор (парсит) кадра канального уровня на известные протоколы.
        Известные протоколы:
            * Канальный уровень: Ethernet II
            * Сетевой уровень: IPv4
            * Транспортный уровень: TCP, UDP
            * Прикладной уровень: POP3
        :param frame: кадр канального уровня в виде байт
        :return: экземпляр класса ResultSet либо None, если обработка данных не завершена
        """
        ethernet_frame = EthernetII.parse(frame)
        if ethernet_frame.ether_type == EthernetII.ETHER_TYPE_IPv4:  # IP-пакет
            ip_packet = IPProtocol.parse(ethernet_frame.data)
            ethernet_frame.data = ip_packet

            # Предварительная инициализация
            data = None             # Данные от прикладного уровня
            file_extension = None   # Расширение файла с данными от прикладного уровня

            if ip_packet.protocol == IPProtocol.TCP:  # TCP-сегмент
                tcp_segment = TCPProtocol.parse(ip_packet.data)
                ip_packet.data = tcp_segment

                if not tcp_segment.data:      # Расносильно len(tcp_segment.data) != 0
                    if POP3.PORT in (tcp_segment.src_port, tcp_segment.dst_port):
                        data = POP3.parse(tcp_segment.data)
                        file_extension = '.eml'  # Расширение сообщений электронной почты

                    # TODO SMTP-protocol
                    # TODO HTTP-protocol
                    # TODO FTP-protocol

            elif ip_packet.protocol == IPProtocol.UDP:
                udp_datagram = UDPProtocol.parse(ip_packet.data)

                # TODO интересует только ответ от сервера
                if DNS.PORT in (udp_datagram.src_port, udp_datagram.dst_port):
                    dns_message = DNS.parse(udp_datagram.data)
                    if dns_message is not None:
                        data = dns_message.get_data()
                        file_extension = dns_message.get_file_extension()

            # Подготовка ResultSet для ответа/возврата
            if (data is not None) and (file_extension is not None):
                result_set = ResultSet(ip_packet.src_ip, ip_packet.dst_ip, data, file_extension)
                return result_set
            else:
                return None
