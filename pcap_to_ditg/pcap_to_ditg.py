#!/usr/bin/env python

import dpkt
import datetime
import linecache
import os
import socket
from util import util


class pcap_to_ditg(object):
    """ Generate DITG script files from a pcap file """

    __IpMapDict = {}
    __Flows = {}
    __p = 12346 #TODO later add for separate command-line option
    __p_end = 12752 #TODO later add for separate command-line option

    def __init__(self,
        pcap_file,
        mapper_file,
        list_file,
        options = {
            'remove_old': False,
            'same_dir' : False,
            'start_time' : 0,
            'end_time' : 30,
        }
    ):
        super(pcap_to_ditg, self).__init__()
        self.pcap_file = pcap_file
        self.mapper_file = mapper_file
        self.list_file = list_file
        self.options = options

        if (self.options['remove_old']):
            os.system('rm -r *_ditg_files')

        # Generate Map in IpMapDict
        self.__generateMapper()
        self.__openAndReadPcap()

    # utility methods
    @classmethod
    def __getKey(self, src_ip, dst_ip):
        return src_ip + "_" + dst_ip

    # Generates an un-reserved Port number
    def __getDstPort(self):
        if self.__p == 12752:
            self.__p = 12346
        else:
            self.__p += 1

        return self.__p

    @classmethod
    def __getSrcIPAddrFromKey(self, key, mapped = False):
        if mapped == False:
            return (key.split("_"))[0]
        elif self.__IpMapDict != None:
            if key.split('_')[0] in self.__IpMapDict.keys():
                return self.__IpMapDict[key.split('_')[0]]

        return ''

    @classmethod
    def __getDstIPAddrFromKey(self, key, mapped = False):
        if mapped == False:
            return (key.split("_"))[1]
        elif self.__IpMapDict != None:
            if key.split('_')[1] in self.__IpMapDict.keys():
                return self.__IpMapDict[key.split('_')[1]]

        return ''

    def __addToFlows(self, key, timestamp, type='TCP'):
        if key in self.__Flows.keys():
            l = self.__Flows[key]
        else:
            l = []

        l.append(timestamp)
        self.__Flows[key] = l

    @classmethod
    def __getIpForHost(self, host):
        if host == 'h1':
            return '10.0.1.10'
        elif host == 'h2':
            return '10.0.1.20'
        elif host == 'h3':
            return '10.0.2.10'
        elif host == 'h4':
            return '10.0.2.20'
        elif host == 'h5':
            return '10.0.10.1'
        elif host == 'h6':
            return '10.0.5.2'

    def __writeFlowToFile(self, key):
        origSIP = self.__getSrcIPAddrFromKey(key)
        origDIP = self.__getDstIPAddrFromKey(key)
        newSIP  = self.__getSrcIPAddrFromKey(key, True)
        newDIP  = self.__getDstIPAddrFromKey(key, True)

        if newDIP == '' or newSIP == '':
            return
        if not os.path.exists(newSIP + '_ditg_files'):
            os.makedirs(newSIP + '_ditg_files')

        scriptFileName = newSIP + '_ditg_files/' + newSIP + '.ditg'
        if os.path.exists(scriptFileName):
            f = open(scriptFileName, 'a')
        else:
            f = open(scriptFileName, 'w')

        idtsFileName = newSIP + '_ditg_files/' + origSIP + '_' + origDIP + '.idts'
        idtsFile = open(idtsFileName, 'w')

        idts = self.__Flows[key]
        for idt in idts:
            idtsFile.write(str(idt) + '\n')
        idtsFile.close()

        f.write(
            '-z ' + str(len(idts)) + \
            ' -a ' + newDIP + \
            ' -rp '+ str(self.__getDstPort()) + \
            ' -n 800 200 ' + \
            ' -Ft ' + idtsFileName + \
            ' -T TCP' + '\n'
        )

        f.close()

    def __readPartitions(self):
        Partitions = {}
        i = 0
        with open(self.mapper_file, 'r') as f:
            for line in f:
                if i == 0:
                    i += 1
                    continue

                if ',' in line:
                    host  = line.split(',')[0]
                    endPoints = []
                    endPoints.append(line.split(',')[1]) # start
                    endPoints.append(line.split(',')[2]) # end
                    Partitions[host] = endPoints
        return Partitions

    def __generateMapper(self):
        Partitions = self.__readPartitions()

        i = 0
        for p in Partitions.keys():
            endPoints = Partitions[p]
            for i in range(int(endPoints[0]), int(endPoints[1]) + 1):
                ip = linecache.getline(self.list_file, i).strip().strip(',')
                (self.__IpMapDict)[ip] = pcap_to_ditg.__getIpForHost(p)

    def __openAndReadPcap(self):
        f = open(self.pcap_file)
        pcap = dpkt.pcap.Reader(f)
        first = True
        i = 0

        first_time = 0

        for ts, buf in pcap:
            if ts < self.options['start_time']:
                continue

            if first:
                first_time = ts
                first = False

            if first == False and (ts - first_time) >= self.options['end_time']:
                break
            else:
                pass

            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except Exception, e:
                continue

            if eth.type!=dpkt.ethernet.ETH_TYPE_IP:
                continue
                # Skip if it is not an IP packet

            ip=eth.data
            if ip.p == dpkt.ip.IP_PROTO_TCP: # Check for TCP packets
                TCP = ip.data
                key = pcap_to_ditg.__getKey(util.inet_to_str(ip.src), util.inet_to_str(ip.dst))

                self.__addToFlows(key, (ts - first_time))
            elif ip.p == dpkt.ip.IP_PROTO_UDP: # Check for UDP packets
                UDP = ip.data
                key = pcap_to_ditg.__getKey(util.inet_to_str(ip.src), util.inet_to_str(ip.dst))

                self.__addToFlows(key, (ts - first_time), 'UDP')
            else:
                # ignore other packets
                continue
            i += 1

        f.close()

    # API 1
    def getAllDistinctIPs(self):
        ipsProcessed = []
        for key in self.__Flows.keys():
            origSIP = pcap_to_ditg.__getSrcIPAddrFromKey(key)
            if origSIP not in ipsProcessed:
                ipsProcessed.append(origSIP)

            origDIP = pcap_to_ditg.__getDstIPAddrFromKey(key)
            if origDIP not in ipsProcessed:
                ipsProcessed.append(origDIP)

        return ipsProcessed

    # API 2
    def generateDITGFlowFiles(self):
        i = 0
        for key in self.__Flows.keys():
            i += 1
            self.__writeFlowToFile(key)
