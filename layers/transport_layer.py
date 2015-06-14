# coding: utf-8

__author__ = 'vadim'

class TCPProtocol:

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
