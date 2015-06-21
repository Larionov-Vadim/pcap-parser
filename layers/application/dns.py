# coding: utf-8
import socket
from struct import unpack

__author__ = 'vadim'


class DNS:
    PORT = 53
    HEADER_LENGTH = 12          # Размер заголовка в байтах

    def __init__(self):
        self.header = None
        self.queries = list()
        self.answers = list()
        self.authorities = list()
        self.additions = list()

    def __str__(self):
        return 'Id: ' + str(self.header.id) + \
               ' Flags: ' + str(self.header.flags_and_codes) + \
               ' Question_count: ' + str(self.header.question_count) + \
               ' Answer_record_count: ' + str(self.header.answer_record_count) + \
               ' Authority_record_count: ' + str(self.header.authority_record_count) + \
               ' Additional_record_count: ' + str(self.header.additional_record_count)

    def get_data(self):
        data = '---Header--\n'
        data += 'Id: {0} ({1})\n'.format(self.header.id, hex(self.header.id))
        data += 'Question Count: {}\n'.format(self.header.question_count)
        data += 'Answer Record Count: {}\n'.format(self.header.answer_record_count)
        data += 'Authority Record Count: {}\n'.format(self.header.authority_record_count)
        data += 'Additional Record Count: {}\n\n'.format(self.header.additional_record_count)

        for query in self.queries:
            data += '---Question---\n'
            data += 'Name: {}\n'.format(query.name)
            data += 'Type: {}\n'.format(DNS._Type.get_name(query.type))
            data += 'Class: {}\n'.format(DNS._Clazz.get_name(query.clazz))
        data += '\n'

        f = [('Answers', self.answers),
             ('Authorities', self.authorities,),
             ('Additions', self.additions)]

        for title, list_records in f:
            if list_records:
                data += '---{}---\n'.format(title)

            if title == 'Answers' and not list_records:
                data += '---{}---\nEmpty Answer\n'.format(title)

            count = 0
            for record in list_records:
                data += '-{0}[{1}]-\n'.format(title, count)
                count += 1
                data += 'Name: {}\n'.format(record.name)
                data += 'Type: {}\n'.format(DNS._Type.get_name(record.type))
                data += 'Class: {}\n'.format(DNS._Clazz.get_name(record.clazz))
                data += 'TTL: {} seconds\n'.format(record.TTL)
                data += 'Data length: {}\n'.format(record.data_length)
                data += 'Data: ({})\n'.format(record.resource_data)
                data += '\n'
        return data

    def get_file_extension(self):
        return '.dns'

    @staticmethod
    def parse(message):
        # Секция заголовка
        header, position = DNS.Header.parse(message[:DNS.HEADER_LENGTH])

        # Смотрим только флаг QR - тип запроса
        # Если это отклик (1), то парсим, иначе пропускаем (skip)
        if ((header.flags_and_codes & (0x1 << 15)) >> 15) == 0b1:
            dns_message = DNS()
            dns_message.header = header

            # Секция запросов
            for i in range(header.question_count):
                query, position = DNS.Query.parse(message, position)
                dns_message.queries.append(query)

            # Секция откликов
            for i in range(header.answer_record_count):
                answer, position = DNS.ResourceRecord.parse(message, position)
                dns_message.answers.append(answer)

            # Секция прав доступа
            for i in range(header.authority_record_count):
                authority, position = DNS.ResourceRecord.parse(message, position)
                dns_message.authorities.append(authority)

            # Секция дополнительной информации
            for i in range(header.additional_record_count):
                addition, position = DNS.ResourceRecord.parse(message, position)
                dns_message.additions.append(addition)

            return dns_message
        return None

    # Формируем url (name) DNS-запроса
    @staticmethod
    def _parse_name(query):
        url = str()
        position = 1  # Позиция начала символов
        count = int(ord(query[position - 1]))  # Количество символов в url-е
        while count != 0:
            url += query[position: position + count]
            url += '.'
            position += count + 1
            count = int(ord(query[position - 1]))

        if url.endswith('.'):
            url = url[:-1]

        return url, position

    @staticmethod
    def _get_offset(counter):
        if (counter & (0x03 << 14)) >> 14 == 0b11:  # 2 старших бита равны '0b11'
            return counter & ~(0x03 << 14)
        else:
            return -1

    @staticmethod
    def _parse_info(message, position, data_length=None):
        pos = position
        info = str()

        if data_length is None:
            data_length = 1000          # Выход из цикла будет произведён через break

        while pos != position + data_length:
            # Если это указатель
            if ((ord(message[pos]) & 0b11000000) >> 6) == 0b11:
                # TODO имена
                counter = unpack('!H', message[pos: pos + 2])[0]
                pos += 2
                offset = counter & ~(0x03 << 14)

                # Считываем часть
                count = ord(message[offset])
                info += message[offset + 1: offset + 1 + count]
                info += '.'

            # Иначе символьная запись
            else:
                counter = ord(message[pos])
                if counter == 0:
                    break
                pos += 1
                info += message[pos: pos + counter]
                pos += counter
                info += '.'

        if info.endswith('.'):
            info = info[:-1]
        return info, pos

    class Header:

        def __init__(self):
            self.id = None
            self.flags_and_codes = None
            self.question_count = None
            self.answer_record_count = None
            self.authority_record_count = None
            self.additional_record_count = None

        def __str__(self):
            return 'Id: ' + str(self.id) + \
                   ' Flags_and_codes: ' + str(bin(self.flags_and_codes)) + \
                   ' Question_count: ' + str(self.question_count) + \
                   ' Answer_record_count: ' + str(self.answer_record_count) + \
                   ' Authority_record_count: ' + str(self.authority_record_count) + \
                   ' Additional_record_count: ' + str(self.additional_record_count)

        @staticmethod
        def parse(message):
            dnsh = unpack('!HHHHHH', message[:DNS.HEADER_LENGTH])
            header = DNS.Header()
            header.id = dnsh[0]
            header.flags_and_codes = dnsh[1]
            header.question_count = dnsh[2]
            header.answer_record_count = dnsh[3]
            header.authority_record_count = dnsh[4]
            header.additional_record_count = dnsh[5]
            return header, DNS.HEADER_LENGTH

    class Query:

        def __init__(self):
            self.name = None
            self.type = None
            self.clazz = None

        def __str__(self):
            return 'Name: ' + str(self.name) + \
                   ' Type: ' + str(self.type) + \
                   ' Class: ' + str(self.clazz)

        @staticmethod
        def parse(message, position):
            query = DNS.Query()
            query.name, pos = DNS._parse_name(message[position:])
            position += pos
            query.type, query.clazz = unpack('!HH', message[position: position + 4])
            position += 4
            return query, position

    class ResourceRecord:

        def __init__(self):
            self.name = None
            self.type = None
            self.clazz = None
            self.TTL = None
            self.data_length = None
            self.resource_data = None           # В виде строки

        def __str__(self):
            return 'Name: ' + str(self.name) + \
                   ' Type: ' + str(self.type) + \
                   ' Class: ' + str(self.clazz) + \
                   ' TTL: ' + str(self.TTL) + \
                   ' Data_length: ' + str(self.data_length) + \
                   ' Resouce_data: (' + str(self.resource_data) + ')'

        @staticmethod
        def parse(message, position):
            resource_record = DNS.ResourceRecord()

            resource_record.name, position = DNS._parse_info(message, position)

            resource_record.type, resource_record.clazz, resource_record.TTL, \
                resource_record.data_length = unpack('!HHIH', message[position: position + 10])
            position += 10
            resource_record.resource_data = \
                DNS.ResourceRecord.__parse_resource_data(
                    message, position, resource_record.type, resource_record.data_length
                )

            position += resource_record.data_length
            return resource_record, position

        @staticmethod
        def __parse_resource_data(message, position, answer_type, data_length):
            func = {
                DNS._Type.A: DNS.ResourceRecord.__parse_type_a,
                DNS._Type.TXT: DNS.ResourceRecord.__parse_type_txt,
                DNS._Type.AAAA: DNS.ResourceRecord.__parse_type_aaaa,
                DNS._Type.MX: DNS.ResourceRecord.__parse_type_mx,
                DNS._Type.NS: DNS.ResourceRecord.__parse_type_ns,
                DNS._Type.CNAME: DNS.ResourceRecord.__parse_type_cname,
                DNS._Type.PTR: DNS.ResourceRecord.__parse_type_ptr,

            }.get(answer_type, DNS.ResourceRecord.__parse_unknown_type)

            if not (func == DNS.ResourceRecord.__parse_unknown_type):
                resource_data = func(message, position, data_length)
            else:
                resource_data = func(answer_type)
            return resource_data

        @staticmethod
        def __parse_type_a(message, position, data_length):
            return 'IPv4-address: ' + str(socket.inet_ntoa(message[position: position + data_length]))

        @staticmethod
        def __parse_type_aaaa(message, position, data_length):
            address = 'IPv6 Address: '
            data = message[position: position + data_length]
            for i, j in zip(data[0::2], data[1::2]):
                address += format(ord(i), 'x').zfill(2) + format(ord(j), 'x').zfill(2)
                address += ':'
            if address.endswith(':'):
                address = address[:-1]
            return address

        @staticmethod
        def __parse_type_mx(message, position, data_length):
            info = 'Preference: ' + str(unpack('!H', message[position: position + 2])[0])
            info += '; Mail Exchange: '
            info += DNS._parse_info(message, position + 2, data_length - 2)[0]
            return info

        @staticmethod
        def __parse_type_ns(message, position, data_length):
            info = 'Name Server: '
            info += DNS._parse_info(message, position, data_length)[0]
            return info

        @staticmethod
        def __parse_type_txt(message, position, data_length):
            # Первый байт - длина текстового сообщения
            return 'TXT: ' + str(message[position + 1: position + data_length])

        @staticmethod
        def __parse_type_cname(message, position, data_length):
            info = 'Primary Name: '
            info += DNS._parse_info(message, position, data_length)[0]
            return info

        @staticmethod
        def __parse_type_ptr(message, position, data_length):
            info = 'Domain Name: '
            info += DNS._parse_info(message, position, data_length)[0]
            return info

        @staticmethod
        def __parse_unknown_type(answer_type):
            return 'UNKNOWN TYPE: ' + str(answer_type)

    class _Type:
        """
        Класс констант для типов запроса/ресурсных записей
        """

        __type_names = {
            0x01: 'A',              # 1) IPv4-адрес
            0x02: 'NS',             # 2) Сервер DNS
            0x05: 'CNAME',          # 5) Каноническое имя
            0x0c: 'PTR',            # 12) Запись указателя
            0x0d: 'HINFO',          # 13) Информация о хосте
            0x0f: 'MX',             # 15) Запись об обмене почтой
            0x10: 'TXT',            # 16) Запись произвольных двоичных данных
            0x1c: 'AAAA',           # 28) IPv6-адрес
            0xfc: 'AXFR',           # 252) Запрос на передачу зоны
            0xff: 'ANY',            # 255) Запрос всех записей
        }

        A = 0x01
        NS = 0x02
        CNAME = 0x05
        PTR = 0x0C
        HINFO = 0x0d
        MX = 0x0f
        TXT = 0x10
        AAAA = 0x1C
        AXFR = 0xfc
        ANY = 0xff

        UNKNOWN = -1  # Неизвестный тип

        def __init__(self):
            raise Exception("This is a private constructor")

        @staticmethod
        def get_name(value):
            name = DNS._Type.__type_names.get(value)
            if name is None:
                value_str = format(value, 'x').zfill(4)
                name = 'Unknown type (0x{})'.format(value_str)
            return name

    class _Clazz:
        """
        Класс констант для классов запроса/ресурсных записей
        """

        __class_names = {
            0x0000: 'Reserved',
            0x0001: 'Internet (IN)',
            0x0002: 'Unassigned',
            0x0003: 'Chaos (CH)',
            0x0004: 'Hesiod (HS)',
            0x00FE: 'QCLASS NONE',
            0x00FF: 'QCLASS * (ANY)',
        }

        def __init__(self):
            raise Exception("This is a private constructor")

        @staticmethod
        def get_name(value):
            name = DNS._Clazz.__class_names.get(value)
            if name is None:
                value_str = format(value, 'x').zfill(4)
                name = 'Unknown class (0x{})'.format(value_str)
            return name
