# coding: utf-8
import pcapy
import sys
import os.path
from parser import PcapParser

__author__ = 'vadim'

def main(argv):
    path_file = '/home/vadim/pop3.pcap'
    if not os.path.isfile(path_file):
        print('{0}: No such file'.format(path_file))
        return

    cap = pcapy.open_offline(path_file)
    pcapParser = PcapParser()

    """
    header_cap - заголовок pcap файла (<type 'Pkthdr'>),
    packet - кадр, передаваемый по сети (<type 'str'>)
    Каждая итерация в цикле - это обработка одного кадра
    """
    (header_cap, frame) = cap.next()
    while len(frame) != 0:
        """
        На данный момент вся логика в pcapParser. В последующем нужно вынести её в
        класс StackProtocols, у которого можно будет вызывать необходимые методы
        """
        pcapParser.parse(frame)
        (header_cap, frame) = cap.next()

if __name__ == "__main__":
    main(sys.argv)
