# coding: utf-8

__author__ = 'vadim'


class POP3:
    PORT = 110

    __is_pop3_msg = False       # Переменная, указывающая, что сообщение POP3 является письмом
    __pop3_buf = list()         # Буфер для сборки сообщений протокола POP3

    def __init__(self):
        pass

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
                msg = str()
                for part_msg in POP3.__pop3_buf:
                    msg += part_msg
                msg += message
                del POP3.__pop3_buf[:]  # Очистка буфера
                POP3.__is_pop3_msg = False
                return msg

            else:
                POP3.__pop3_buf.append(message)  # Части письма хранятся в буфере

        elif message[:4].upper().startswith('RETR'):  # Проверка первых 4х символов на соответствие RETR
            POP3.__is_pop3_msg = True  # Следующее сообщение - письмо

        return None
