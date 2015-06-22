# coding: utf-8

__author__ = 'vadim'


class POP3:
    PORT = 110

    __is_pop3_msg = False       # Переменная, указывающая, что сообщение POP3 является письмом
    __pop3_buf = list()         # Буфер для сборки сообщений протокола POP3

    def __init__(self):
        self.data = None

    @staticmethod
    def get_file_extension():
        return '.eml'

    def get_data(self):
        return self.data

    @staticmethod
    def parse(message):
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
        if POP3.__is_pop3_msg:  # Если пришло письмо (часть письма)
            if message[:3].upper().startswith('+OK'):  # Удаление первой строки '+OK' от сервера
                message = message.split('\n', 1)[1]

            if message.endswith('.\r\n'):  # Последняя часть письма (либо цельное письмо)
                pop3_message = POP3()
                pop3_message.data = str()
                for part_msg in POP3.__pop3_buf:
                    pop3_message.data += part_msg
                pop3_message.data += message
                del POP3.__pop3_buf[:]  # Очистка буфера
                POP3.__is_pop3_msg = False
                return pop3_message

            else:
                POP3.__pop3_buf.append(message)  # Части письма хранятся в буфере

        elif message[:4].upper().startswith('RETR'):  # Проверка первых 4х символов на соответствие RETR
            POP3.__is_pop3_msg = True  # Следующее сообщение - письмо

        return None
