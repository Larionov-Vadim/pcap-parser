# coding: utf-8
import pcapy
import sys
import os.path
from parser import PcapParser
from utils import create_dir, create_path_name

__author__ = 'vadim'

def main(argv):
    # base_dir = os.path.dirname(os.path.realpath(__file__))
    base_dir = '/home/vadim/'
    path_file = '/home/vadim/dns.cap'
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
        result_set = pcapParser.parse(frame)

        if result_set is not None:
            dir_path = create_path_name(base_dir, result_set.src_ip, result_set.dst_ip)
            create_dir(dir_path)

            file_name = result_set.generate_file_name()
            with open(create_path_name(dir_path, file_name), mode='w') as f:
                f.write(result_set.data)

        (header_cap, frame) = cap.next()


if __name__ == "__main__":
    main(sys.argv)
    print('Success')
