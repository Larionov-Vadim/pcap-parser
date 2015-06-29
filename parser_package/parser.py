# coding: utf-8
from layers.data_link_layer import EthernetII
from layers.network_layer import IPProtocol
from layers.transport_layer import TCPProtocol, UDPProtocol
from layers.application.pop3 import POP3
from layers.application.dns import DNS
from layers.application.ftp import FTP
from layers.application.http import HTTP
from layers.application.smtp import SMTP
from parser_package.result_set import ResultSet

__author__ = 'vadim'


class PcapParser:
    """
    Парсер сетевого трафика
    """

    file_downloading = False
    FTP_PASSIVE_PORT = None

    def __init__(self):
        pass

    def parse(self, frame):
        """
        Производит разбор (парсит) кадра канального уровня на известные протоколы.
        Известные протоколы:
            * Канальный уровень: Ethernet II
            * Сетевой уровень: IPv4
            * Транспортный уровень: TCP, UDP
            * Прикладной уровень: POP3, FTP, HTTP, SMTP
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
            file_name = None        #Имя файла в случае его наличия

            if ip_packet.protocol == IPProtocol.TCP:  # TCP-сегмент
                tcp_segment = TCPProtocol.parse(ip_packet.data)
                ip_packet.data = tcp_segment

                if tcp_segment.data:                # Расносильно len(tcp_segment.data) != 0
                    if POP3.PORT in (tcp_segment.src_port, tcp_segment.dst_port):
                        pop3_message = POP3.parse(tcp_segment.data)
                        if pop3_message is not None:
                            data = pop3_message.get_data()
                            file_extension = pop3_message.get_file_extension()

                    if SMTP.PORT in (tcp_segment.src_port, tcp_segment.dst_port):
                        data = SMTP.parse(tcp_segment.data)
                        file_extension = '.eml'

                    if HTTP.PORT in (tcp_segment.src_port, tcp_segment.dst_port):
                        HTTP.parse(tcp_segment.data)
                        data = HTTP.get_data()
                        file_extension = HTTP.get_file_extension()

                    #обрабатываем ответы FTP Сервера
                    if (FTP.PORT == tcp_segment.src_port):
                        con=FTP.parse(tcp_segment,ip_packet.src_ip)#объект FTP_CON
                        if(con):#здесь нам вернулся файл
                            file_name = con.FILE_NAME
                            data = con.data
                            file_extension = None
                            self.FTP_PASSIVE_PORT = None


                    #передача файла ведется по рандомно выделенному сервером порту
                    ftp_ports = []
                    if len(FTP.ftp_con)>0:
                        for con in FTP.ftp_con:
                            ftp_ports.append(con.PORT)
                    if (tcp_segment.src_port in ftp_ports):
                        FTP.add_to_file(tcp_segment,ip_packet.src_ip)

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
                result_set = ResultSet(ip_packet.src_ip, ip_packet.dst_ip, data, file_extension, file_name)
                return result_set
            elif(data is not None):#FTP!!!
                result_set = ResultSet(ip_packet.src_ip, ip_packet.dst_ip, data, file_extension, file_name.replace("/","\\"))#экранируем слеши
                return result_set
            else:
                return None
