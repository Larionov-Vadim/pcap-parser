# coding: utf-8
import socket
from struct import unpack

from layers.data_link_layer import EthernetII
from layers.network_layer import IPProtocol
from layers.transport_layer import TCPProtocol
from layers.application_layer import POP3
from result_set import ResultSet

__author__ = 'vadim'


class PcapParser:
    def __init__(self):
        """
        Парсер пакетов сетевого трафика
        :return:
        """
        self.__pop3_buf = list()  # Буфер для сборки сообщений протокола POP3
        self.__is_pop3_msg = False  # Переменная, указывающая, что сообщение POP3 является письмом
        pass

    def parse(self, frame):
        """
        Производит разбор (парсит) кадра канального уровня на известные протоколы.
        Известные протоколы:
            * Канальный уровень: Ethernet II
            * Сетевой уровень: IPv4
            * Транспортный уровень: TCP
            * Прикладной уровень: POP3
        :param frame: кадр канального уровня в виде байт
        :return: экземпляр класса ResultSet либо None, если обработка данных не завершена
        """
        ethernet_frame = self.parse_frame(frame)
        if ethernet_frame.ether_type == EthernetII.ETHER_TYPE_IPv4:  # IP-пакет
            ip_packet = self.parse_ip_packet(ethernet_frame.data)
            ethernet_frame.data = ip_packet

            if ip_packet.protocol == IPProtocol.TCP:  # TCP-сегмент
                tcp_segment = self.parse_tcp_segment(ip_packet.data)
                ip_packet.data = tcp_segment

                # Предварительная инициализация
                data = None                         # Данные от прикладного уровня
                file_extension = None               # Расширение файла с данными от прикладного уровня

                if len(tcp_segment.data) != 0:
                    if POP3.PORT in (tcp_segment.src_port, tcp_segment.dst_port):
                        data = self.parse_pop3(tcp_segment.data)
                        file_extension = '.eml'     # Расширение сообщений электронной почты

                    # TODO SMTP-protocol
                    # TODO HTTP-protocol
                    # TODO FTP-protocol

                # Подготовка ResultSet для ответа/возврата
                if (data is not None) and (file_extension is not None):
                    result_set = ResultSet(ip_packet.src_ip, ip_packet.dst_ip, data, file_extension)
                    return result_set
                else:
                    return None

    def parse_frame(self, frame):
        """
        Парсер кадра канального уровня протокола Ethernet II
        :param frame: кадр канального уровня в виде байт
        :return: экземпляр класса EthernetFrame
        """
        ethernet_length = EthernetII.HEADER_LENGTH  # Длина заголовка кадра в протоколе Ethernet II
        ethernet_header = frame[:ethernet_length]   # Ethernet заголовок
        eth = unpack('!6s6sH', ethernet_header)     # Формирует кортеж согласно параметрам разбора

        ethernet_frame = EthernetII(dst_mac=eth[0], src_mac=eth[1], ether_type=eth[2])
        ethernet_frame.data = frame[ethernet_length:]
        return ethernet_frame

    def parse_ip_packet(self, packet):
        """
        Парсер пакета сетевого уровня протокола IPv4
        :param packet: пакет сетевого уровня протокола IPv4 в виде байт
        :return: экземлпяр класса IpPacket()
        """
        ip_packet = IPProtocol()
        iph = unpack('!BBHHHBBH4s4s', packet[:IPProtocol.HEADER_LENGTH])  # Заголовок IP-пакета без опций

        ip_packet.version = iph[0] >> 4                     # Старшие 4 бита отвечают за версию
        ip_packet.ihl = iph[0] & 0xF                        # Младшие 4 бита отвечают за IHL
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

    def parse_tcp_segment(self, segment):
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

    def parse_pop3(self, message):
        """
        Парсер сообщений протокола POP3.
        Алгоритм обработки сообщений следующий: отслеживается передача команды RETR, после которой
        сервер отсылает письмо. Части письма сохраняются в буфер __pop3_buf. После завершающей
        последовательности символов '.\r\n' формируется цельное письмо в виде строки, которую
        позвращает данный метод.
        :param message: сообщение прикладного уровня
        :return: None, если сообщение содержит часть письма либо что-то другое; str - перехваченное
        цельное письмо
        """
        if self.__is_pop3_msg:                          # Если пришло письмо (часть письма)
            if message[:3].upper().startswith('+OK'):   # Удаление первой строки '+OK' от сервера
                message = message.split('\n', 1)[1]

            if message.endswith('.\r\n'):               # Последняя часть письма (либо цельное письмо)
                msg = str()
                for part_msg in self.__pop3_buf:
                    msg += part_msg
                msg += message
                del self.__pop3_buf[:]                  # Очистка буфера
                self.__is_pop3_msg = False
                return msg

            else:
                self.__pop3_buf.append(message)         # Части письма хранятся в буфере

        elif message[:4].upper().startswith('RETR'):    # Проверка первых 4х символов на соответствие RETR
            self.__is_pop3_msg = True                   # Следующее сообщение - письмо

        return None
