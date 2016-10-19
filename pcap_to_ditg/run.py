#!/usr/bin/env python

import argparse
from pcap_to_ditg import pcap_to_ditg

def getArgParser():
    parser = argparse.ArgumentParser(description='Generate DITG script files from a pcap file')

    # Compulsory args
    parser.add_argument('pcap_file', help='.pcap file to be used in generation',
                        type=str, action='store')
    parser.add_argument('mapper_file', help='Mapper file to be used in generation',
                        type=str, action='store')
    parser.add_argument('list_file', help='File containing all distinct IPs to be used in generation',
                        type=str, action='store')

    # Optional args
    parser.add_argument('-t', '--start-time',  help='Timestamp (in sec) from which the file should be read',
                        type=int, action='store', default=0)
    parser.add_argument('-e', '--end-time',  help='Timestamp (in sec) until which the file should be read',
                        type=int, action='store', default=30)
    parser.add_argument('-r', '--remove-old',
                        help='Remove any older generated files if present before generating new files',
                        action='store_true', default=False)
    parser.add_argument('-s', '--same-dir',
                        help='File containing all distinct IPs to be used in generation',
                        action='store_true', default=False)
    parser.add_argument('-p', '--print-all-ips',
                        help='Print all distinct IPs appearing in the pcap file and exit',
                        action='store_true', default=False)
    parser.add_argument('-c', '--clean',
                        help='Remove any older generated files and exit the program',
                        action='store_true', default=False)

    return parser

if __name__ == "__main__":

    parser = getArgParser()
    args = parser.parse_args()
    options = {
        'remove_old': args.remove_old,
        'same_dir' : args.same_dir,
        'start_time' : int(args.start_time),
        'end_time' : int(args.end_time),
    }

    pToD = pcap_to_ditg(
        args.pcap_file, # Pcap file to read
        args.mapper_file, # File with mapping of IPs to topology hosts
        args.list_file, # File with list of IPs
        options
    )

    if args.print_all_ips:
        ips = pToD.getAllDistinctIPs()
        print
        print('The list of distinct IPs appearing in \'' + args.pcap_file + '\' are:')
        for ip in ips:
            print ip + ','

    else:
        pToD.generateDITGFlowFiles()

        print '\nThe flow scripts and the IDT files have been generated' + \
            ' and have been saved in separate sub-folders *_ditg_files.'
