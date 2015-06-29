# coding: utf-8

__author__ = 'Mily-V'

class HTTP:
    PORT = 80
    __is_http_msg = False       # переменная, указывающая, что пора писать в буфер
    __is_data = False           # переменная, указываюшая, что считывается тело сообщения
    extension = '.'             # расширение файла
    endExtension = 0
    data = str()


    def __init__(self):
        pass

    @staticmethod
    def get_file_extension():
        if (HTTP.extension != '.'):
            return HTTP.extension
        else:
            return None

    @staticmethod
    def get_data():
        if (HTTP.data != ''):
            return HTTP.data
        else:
            return  None

    @staticmethod
    def parse(message):
        """
        Парсер сообщений протокола HTTP.
        Алгоритм обработки следующий:
        смотрим на стартовую строку HTTP-сообщения. Если это ответ от сервера, то анализируем
        заголовки, точнее нужен нам всего один - Content Type. Из его содержимого
        (если он есть, разумеется) запомниаем расширение. Затем ищем
        символы '\r\n', после которой
        посылается тело сообщения, которое по частям сохраняются в строку data.
        :param message: сообщение прикладного уровня
        """

        if (message[0:3] == 'GET'):
            HTTP.__is_http_msg = False
            HTTP.__is_data = False
            HTTP.data = ''
            HTTP.extension = '.'

        if (message[0:4] == 'HTTP'):
            HTTP.__is_http_msg = True

        if HTTP.__is_http_msg:
            msg = message.split('\r\n')
            for part_msg in msg:
                if (part_msg[0:12] == 'Content-Type'):
                    if (part_msg.find(';') != -1):
                        HTTP.endExtension = part_msg.find(';')
                    else:
                        HTTP.endExtension = len(part_msg)
                    HTTP.extension += part_msg[part_msg.find('/')+1:HTTP.endExtension]
                if (part_msg == ''):
                    HTTP.__is_data = True
                if HTTP.__is_data:
                    HTTP.data += part_msg
                    #HTTP.data += '\n'








