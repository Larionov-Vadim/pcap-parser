# coding: utf-8

__author__ = 'Abovyan'

class SMTP:
    PORT = 25

    __is_smtp_msg = False       # Переменная, указывающая, что сообщение SMTP является письмом
    __smtp_buf = list()         # Буфер для сборки сообщений протокола SMTP

    def __init__(self):
        pass

    @staticmethod
    def parse(message):
        """
        Парсер сообщений протокола SMTP.
        Алгоритм обработки сообщений следующий: отслеживается передача команды DATA, после которой
        сервер отсылает письмо. Части письма сохраняются в буфер __smtp_buf. После завершающей
        последовательности символов '.\r\n' формируется цельное письмо в виде строки, которую
        позвращает данный метод.
        :param message: сообщение прикладного уровня
        :return: None, если сообщение содержит часть письма либо что-то другое; str - перехваченное
        цельное письмо
        """
        if SMTP.__is_smtp_msg:  # Если пришло письмо (часть письма)
            if message[:3].upper().startswith('354'):  # Удаление первой строки 'enter message' от сервера
                message = message.split('\n', 1)[1]

            if ( ('\r\n.\r\n' in message) and (len(message) <= 6) ) or ( message.endswith('.\r\n') ) :  # Последняя часть письма (либо цельное письмо)
                msg = str()
                for part_msg in SMTP.__smtp_buf:
                    msg += part_msg
                msg += message
                del SMTP.__smtp_buf[:]  # Очистка буфера
                SMTP.__is_smtp_msg = False
                return msg

            else:
                SMTP.__smtp_buf.append(message)  # Части письма хранятся в буфере

        elif message[:4].upper().startswith('DATA'):  # Проверка первых 4х символов на соответствие DATA
            SMTP.__is_smtp_msg = True  # Следующее сообщение - письмо

        return None
