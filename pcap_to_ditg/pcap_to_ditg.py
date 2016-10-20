#!/usr/bin/env python

# Generate DITG script files from a pcap file
# Copyright (C) 2016  Deven Bansod
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

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
    __p = 12346
    __p_end = 12752

    def __init__(self,
        pcap_file,
        mapper_file,
        list_file,
        options = {
            'start_time' : 0,
            'end_time' : 30,
            'ps_opts': '',
            'port_start': 0,
            'port_end': 0,
        }
    ):
        super(pcap_to_ditg, self).__init__()
        self.pcap_file = pcap_file
        self.mapper_file = mapper_file
        self.list_file = list_file
        self.options = options

        if 'start_time' not in options.keys():
            self.options['start_time'] = 0
        if 'end_time' not in options.keys():
            self.options['end_time'] = 30
        if 'ps_opts' not in options.keys() or options['ps_opts'] == None:
            self.options['ps_opts'] = ''
        if 'port_start' not in options.keys():
            self.options['port_start'] = 12346
        if 'port_end' not in options.keys():
            self.options['port_end'] = 12752

        self.__p = self.options['port_start']
        self.__p_end = self.options['port_end']

        # Generate Map in IpMapDict
        self.__generateMapper()

        # Read the pcap file into memory
        self.__openAndReadPcap()

    # utility methods
    @classmethod
    def __getKey(self, src_ip, dst_ip):
        return src_ip + "_" + dst_ip

    # Generates an un-reserved Port number
    def __getDstPort(self):
        if self.__p == self.options['port_end']:
            self.__p = self.options['port_start']
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

    def __addToFlows(self, key, timestamp, size, rp, L4type='TCP'):
        if key in self.__Flows.keys():
            l = self.__Flows[key]
        else:
            l = [[], [], [], []]

        l[0].append(timestamp)
        l[1].append(size)
        l[2] = L4type
        l[3] = rp
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

        idts = self.__Flows[key][0]
        for idt in idts:
            idtsFile.write(str(idt) + '\n')
        idtsFile.close()

        flow_str = '-z ' + str(len(idts)) + \
            ' -a ' + newDIP

        if self.options['port_start'] == 0 :
            port_opts = ' -rp ' + self.__Flows[key][3]
        else:
            port_opts = ' -rp ' + str(self.__getDstPort())

        psStr = ''
        if self.options['ps_opts'] == '':
            psFileName = newSIP + '_ditg_files/' + origSIP + '_' + origDIP + '.ps'
            psFile = open(psFileName, 'w')

            pss = self.__Flows[key][1]
            for ps in pss:
                psFile.write(str(ps) + '\n')
            psFile.close()
            psStr = ' -Fs ' + (origSIP + '_' + origDIP + '.ps')
        else:
            psStr = self.options['ps_opts']

        flow_str += ' ' + psStr + ' '
        flow_str += ' -Ft ' + (origSIP + '_' + origDIP + '.idts') + \
            ' -T ' + self.__Flows[key][2] + '\n'

        f.write(flow_str)
        f.close()

    def __readPartitions(self):
        Partitions = {}
        i = 0
        try:
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
        except Exception, e:
            print('*** The file \'' + self.mapper_file + '\' not found\n')
            raise e

    def __generateMapper(self):
        Partitions = self.__readPartitions()

        i = 0
        for p in Partitions.keys():
            endPoints = Partitions[p]
            if os.path.exists(self.list_file):
                for i in range(int(endPoints[0]), int(endPoints[1]) + 1):
                    ip = linecache.getline(self.list_file, i).strip().strip(',')
                    (self.__IpMapDict)[ip] = pcap_to_ditg.__getIpForHost(p)
            else:
                print('*** The file \'' + self.list_file + '\' could not be read\n')
                raise IOError('The file \'' + self.list_file + '\' could not be read\n')

    def __openAndReadPcap(self):
        try:
            f = open(self.pcap_file)
        except Exception, e:
            print('*** The file \'' + self.pcap_file + '\' could not be read\n')
            raise e

        pcap = dpkt.pcap.Reader(f)
        first = True
        i = 0

        first_time = 0
        for ts, buf in pcap:
            first_time = ts
            break

        for ts, buf in pcap:
            if (ts - first_time) < float(self.options['start_time']):
                continue

            if (ts - first_time) >= self.options['end_time']:
                break
            else:
                pass

            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except Exception, e:
                continue

            if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                continue
                # Skip if it is not an IP packet

            ip = eth.data
            if ip.p == dpkt.ip.IP_PROTO_TCP: # Check for TCP packets
                TCP = ip.data
                key = pcap_to_ditg.__getKey(util.inet_to_str(ip.src), util.inet_to_str(ip.dst))

                self.__addToFlows(
                    key,
                    (ts - first_time - self.options['start_time']),
                    len(buf),
                    str(TCP.dport)
                )
            elif ip.p == dpkt.ip.IP_PROTO_UDP: # Check for UDP packets
                UDP = ip.data
                key = pcap_to_ditg.__getKey(util.inet_to_str(ip.src), util.inet_to_str(ip.dst))

                self.__addToFlows(
                    key,
                    (ts - first_time - self.options['start_time']),
                    len(buf),
                    str(UDP.dport),
                    'UDP'
                )
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
        # Remove old files
        os.system('rm -rf *_ditg_files')

        i = 0
        for key in self.__Flows.keys():
            i += 1
            self.__writeFlowToFile(key)
