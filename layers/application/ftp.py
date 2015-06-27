# coding: utf-8

__author__ = 'mid'


class FTP:
    PORT = 21
    i = 1
    PAS_PORT = None#порт на сервере для пассивного режима когда мы подключаемся к нему.
    SERVER_ADDRESS = None#IP  адрес сервера
    FILE_NAME = None
    data = ""

    def __init__(self):
        self.data = ""

    def get_data(self):
        return self.data

    @staticmethod
    def parse(message):
        """
        Парсер сообщений протокола FTP
        сначала команда PASV(227) - возвращает ответом адрес и порт подключения к FTP серверу
        после этого посылается команда RETR и по внешнему адресу и порту мы посылаем пустой пакет
        а FTP сервер отвечает нам пакетами с кусками файла, которые мы склеиваем
        После этого сервер посывает сообщение о конце файла(226)
        """
        message
        if (message.data[0:3]=="227"):#ответ на PASSV
            #беерм ip И порт из ответа
            data = (message.data[message.data.find("(")+1:len(message.data)-4]).split(',')#берем данные из ответа и загоняем их в лист
            FTP.PAS_PORT = int(data[4])*256+int(data[5])
            FTP.SERVER_ADDRESS = data[0]+"."+data[1]+"."+data[2]+"."+data[3]
            return None
        elif (message.data[0:3]=="150"):#ответ на RETR
            #берем имя файла
            if (message.data[message.data.find("/"):message.data.find("(")-1] != ""):
                FTP.FILE_NAME=message.data[message.data.find("/"):message.data.find("(")-1]
                FTP.data=""
                return None
        elif (message.data[0:3]=="226" and FTP.FILE_NAME):#конец передачи файла
            PAS_PORT = None
            return FTP.data

    @staticmethod
    def add_to_file(message):
        if (FTP.FILE_NAME):
            FTP.data+=message

    @staticmethod
    def get_file_name():
        return FTP.FILE_NAME


