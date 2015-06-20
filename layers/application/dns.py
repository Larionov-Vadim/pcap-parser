# coding: utf-8
import socket
from struct import unpack

__author__ = 'vadim'


class DNS:
    PORT = 53
    HEADER_LENGTH = 12              # Размер заголовка в байтах

    def __init__(self):
        self.header = None
        self.queries = list()
        self.answers = list()

    def __str__(self):
        return 'Id: ' + str(self.header.id) +\
                ' Flags: ' + str(self.header.flags_and_codes) +\
                ' Question_count: ' + str(self.header.question_count) +\
                ' Answer_record_count: ' + str(self.header.answer_record_count) +\
                ' Authority_record_count: ' + str(self.header.authority_record_count) +\
                ' Additional_record_count: ' + str(self.header.additional_record_count)

    def get_data(self):
        data = 'Id: ' + str(self.header.id)
        # TODO
        data += '\n---Questions---'
        count = 1
        for query in self.queries:
            data += '\nQuestion ' + str(count)
            count += 1
            data += '\nName: ' + str(query.name)
            data += '\nType: ' + str(query.type)
            data += '\nClass: ' + str(query.clazz)
            data += '\n'

        data += '\n---Answers---'
        count = 1
        for answer in self.answers:
            data += '\nAnswer ' + str(count)
            count += 1
            data += '\nName: ' + str(answer.name)
            data += '\nType: ' + str(answer.type)
            data += '\nClass: ' + str(answer.clazz)
            data += '\nTTL: ' + str(answer.TTL)
            data += '\nData length: ' + str(answer.data_length)
            data += '\nData: (' + str(answer.resource_data)
            data += ')\n'

        return data

    def get_file_extension(self):
        return '.dns'

    @staticmethod
    def parse(message):
        dns_message = DNS()

        # Секция заголовка
        header, position = DNS.Header.parse(message[:DNS.HEADER_LENGTH])
        dns_message.header = header

        # Смотрим только флаг QR - тип запроса
        # Если это отклик (1), то парсим, иначе пропускаем (skip)
        if ((header.flags_and_codes & (0x1 << 15)) >> 15) == 0b1:

            # Секция запросов
            for i in range(header.question_count):
                query, position = DNS.Query.parse(message, position)
                dns_message.queries.append(query)

            # Секция откликов
            for i in range(header.answer_record_count):
                answer, position = DNS.Answer.parse(message, position)
                dns_message.answers.append(answer)

            return dns_message
        return None

    # Формируем url (name) DNS-запроса
    @staticmethod
    def parse_url(query):
        url = str()
        position = 1                            # Позиция начала символов
        count = int(ord(query[position - 1]))   # Количество символов в url-е
        while count != 0:
            url += query[position: position + count]
            url += '.'
            position += count + 1
            count = int(ord(query[position - 1]))

        if url.endswith('.'):
            url = url[:-1]

        return url, position

    @staticmethod
    def get_offset(counter):
        if (counter & (0x03 << 14)) >> 14 == 0b11:  # 2 старших бита равны '0b11'
            return counter & ~(0x03 << 14)
        else:
            print('COUNTEER!: ' + str(hex(counter)))
            return -1

    class Header:

        def __init__(self):
            self.id = None
            self.flags_and_codes = None
            self.question_count = None
            self.answer_record_count = None
            self.authority_record_count = None
            self.additional_record_count = None

        def __str__(self):
            return 'Id: ' + str(self.id) +\
                    ' Flags_and_codes: ' + str(bin(self.flags_and_codes)) +\
                    ' Question_count: ' + str(self.question_count) +\
                    ' Answer_record_count: ' + str(self.answer_record_count) +\
                    ' Authority_record_count: ' + str(self.authority_record_count) +\
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
            return 'Name: ' + str(self.name) +\
                    ' Type: ' + str(self.type) +\
                    ' Class: ' + str(self.clazz)

        @staticmethod
        def parse(message, position):
            query = DNS.Query()
            query.name, pos = DNS.parse_url(message[position:])
            position += pos
            query.type, query.clazz = unpack('!HH', message[position: position + 4])
            position += 4
            return query, position

    class Answer:

        def __init__(self):
            self.name = None
            self.type = None
            self.clazz = None
            self.TTL = None
            self.data_length = None
            self.resource_data = None       # Сделаю строкой

        def __str__(self):
            return 'Name: ' + str(self.name) +\
                    ' Type: ' + str(self.type) +\
                    ' Class: ' + str(self.clazz) +\
                    ' TTL: ' + str(self.TTL) +\
                    ' Data_length: ' + str(self.data_length) +\
                    ' Resouce_data: (' + str(self.resource_data) + ')'

        @staticmethod
        def parse(message, position):
            answer = DNS.Answer()

            name_offset = DNS.get_offset(unpack('!H', message[position: position + 2])[0])
            position += 2
            answer.name, ignore_pos = DNS.parse_url(message[name_offset:])

            answer.type, answer.clazz, answer.TTL,\
            answer.data_length = unpack('!HHIH', message[position: position + 10])
            position += 10
            answer.resource_data = \
                DNS.Answer.__parse_resource_data(
                    message[position: position + answer.data_length], answer.type
                )
            position += answer.data_length
            return answer, position

        @staticmethod
        def __parse_resource_data(data, answer_type):
            func = {
                DNS._type.A: DNS.Answer.__parse_type_a,
                DNS._type.TXT: DNS.Answer.__parse_type_txt,
                DNS._type.AAAA: DNS.Answer.__parse_type_aaaa,
            }.get(answer_type, DNS.Answer.__parse_unknown_type)

            if not (func == DNS.Answer.__parse_unknown_type):
                resource_data = func(data)
            else:
                resource_data = func(answer_type)
            return resource_data

        @staticmethod
        def __parse_type_a(data):
            return 'IPv4-address: ' + str(socket.inet_ntoa(data))

        @staticmethod
        def __parse_type_ns(data):
            return 'Name Server: ' + 'TODO'  # TODO

        @staticmethod
        def __parse_type_aaaa(data):
            return 'IPv6 Address: TODO' # TODO

        @staticmethod
        def __parse_type_txt(data):
            # Первое число - длина
            return 'TXT: ' + str(data[1:])

        @staticmethod
        def __parse_unknown_type(answer_type):
            return 'UNKNOWN TYPE: ' + str(answer_type)

    class _type:
        """
        Класс констант для типов запроса/ресурсных записей
        """
        A = 0x01                # 1) IPv4-адрес
        NS = 0x02               # 2) Сервер DNS
        CNAME = 0x05            # 5) Каноническое имя
        PTR = 0x0C              # 12) Запись указателя
        HINFO = 0x0d            # 13) Информация о хосте
        MX = 0x0f               # 15) Запись об обмене почтой
        TXT = 0x10              # 16) Запись произвольных двоичных данных
        AAAA = 0x1C             # 28) IPv6-адрес
        AXFR = 0xfc             # 252) Запрос на передачу зоны
        ANY = 0xff              # 255) Запрос всех записей

        UNKNOWN = -1            # Неизвестный тип

        def __init__(self):
            raise Exception("This is a private constructor")
