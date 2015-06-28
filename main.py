# coding: utf-8
import pcapy
import sys
import os.path
from argparse import ArgumentParser
from parser_package.parser import PcapParser
from utils import create_path_name, create_dir

__author__ = 'vadim'

def main(args):
    cap = pcapy.open_offline(args.path_file)
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
            dir_path = create_path_name(args.base_dir, result_set.src_ip, result_set.dst_ip)
            create_dir(dir_path)
            if (result_set.file_name):#FTP   потомучто нужно сохранить имя файла
                file_name=result_set.file_name
            else:#не FTP
                file_name = result_set.generate_file_name()
            with open(create_path_name(dir_path, file_name), mode='w') as f:
                f.write(result_set.data)

        (header_cap, frame) = cap.next()


if __name__ == "__main__":
    arg_parser = ArgumentParser(description='*.pcap files parser')
    arg_parser.add_argument('path_file', type=str, help='The path to the .pcap file')
    arg_parser.add_argument('-d', '--dir', '--destination',
                            type=str, dest='base_dir',
                            default=os.path.dirname(os.path.realpath(__file__)),
                            help='The path to save the files')
    args = arg_parser.parse_args()

    if not os.path.isfile(args.path_file):
        print('{0}: No such file'.format(args.path_file))
        sys.exit(1)

    main(args)
    print('Success')
    print('Directory: {}'.format(args.base_dir))
