# coding: utf-8

__author__ = 'mid'

class ftp_con:
    PORT = None
    IP = None
    FILE_NAME = None
    data = ""
    i = 0

class FTP:
    PORT = 21
    i = 1
    ftp_con = []

    def __init__(self):
        self

    @staticmethod
    def parse(message,ip):
        """
        Парсер сообщений протокола FTP
        сначала команда PASV(227) - возвращает ответом адрес и порт подключения к FTP серверу
        после этого посылается команда RETR и по внешнему адресу и порту мы посылаем пустой пакет
        а FTP сервер отвечает нам пакетами с кусками файла, которые мы склеиваем
        После этого сервер посывает сообщение о конце файла(226)
        """

        if (message.data[0:3]=="227"):#ответ на PASSV
            #беерм ip И порт из ответ)
            data = (message.data[message.data.find("(")+1:message.data.find(")")]).split(',')#берем данные из ответа и загоняем их в лист
            #подразумевается, что по команде 226 соединение сбрасывается
            new_con = ftp_con()
            new_con.PORT = int(data[4])*256+int(data[5])
            new_con.IP = data[0]+"."+data[1]+"."+data[2]+"."+data[3]#пассивный порт, который открываем МЫ
            FTP.ftp_con.append(new_con)
            return None
        elif (message.data[0:3]=="150" and message.data.find('/')>0):#ответ на RETR
            #берем имя файла, для этого мы смотрим в соединениях совпадающее по IP адресу и без имени файла
            for con in FTP.ftp_con:
                if (con.IP == ip):
                    con.FILE_NAME = message.data[message.data.find('/'):message.data.find('(')-1]
                    return None

        elif (message.data[0:3]=="226"):#конец передачи файла
            i = 0
            for con in FTP.ftp_con:
                if (con.IP==ip):
                    if (con.FILE_NAME):
                        return FTP.ftp_con.pop(i)#для файлов
                    else:
                        FTP.ftp_con.pop(i)#для не файлов
                        return None
                i += 1

    @staticmethod
    def add_to_file(message,ip):
        #по порту и ип определяем куда вставлять
        for con in FTP.ftp_con:
            if (con.PORT == message.src_port and con.IP == ip and con.FILE_NAME):
                con.data +=message.data





