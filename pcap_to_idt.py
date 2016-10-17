#!/usr/bin/env python

import dpkt
import datetime
import socket
import linecache
import os

def mac_addr(address):
    """Convert a MAC address to a readable/printable string

       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    return ':'.join('%02x' % ord(b) for b in address)

def inet_to_str(inet):
    """Convert inet object to a string

        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
    """
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

def getKey(src_ip, src_port, dst_ip, dst_port):
    return src_ip + ":" + str(src_port) + "-" + dst_ip + ":" + str(dst_port)

def getSrcIPAddrFromKey(key, mapped = False, IpMapDict = None):
    if mapped == False:
        return (key.split(":"))[0]
    elif IpMapDict != None:
        if key.split(':')[0] in IpMapDict.keys():
            return IpMapDict[key.split(':')[0]]

    return ''

def getDstIPAddrFromKey(key, mapped = False, IpMapDict = None):
    dstPair = (key.split("-"))[1]
    if mapped == False:
        return (dstPair.split(":"))[0]
    elif IpMapDict != None:
        if (dstPair.split(":"))[0] in IpMapDict.keys():
            return IpMapDict[(dstPair.split(":"))[0]]

    return ''

def getSrcPortFromKey(key):
    srcPair = (key.split("-"))[0]
    return (srcPair.split(":"))[1]

def getDstPortFromKey(key):
    dstPair = (key.split("-"))[1]
    return (dstPair.split(":"))[1]

def getDstPort():
    global p

    if p == 12752:
        p = 12346
    else:
        p += 1

    return p

def addToTCPFlow(TCPFlows, key, timestamp):
    if key in TCPFlows.keys():
        l = TCPFlows[key]
    else:
        l = []

    l.append(timestamp)
    TCPFlows[key] = l

def addToUDPFlow(UDPFlows, key, timestamp):
    if key in UDPFlows.keys():
        l = UDPFlows[key]
    else:
        l = []

    l.append(timestamp)
    UDPFlows[key] = l

def getIpForHost(host):
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

def generateDITGFlowFiles(TCPFlows, UDPFlows, IpMapDict):
    srcProcessedUDP = []
    srcProcessedTCP = []

    for key in UDPFlows.keys():
        src_ip = getSrcIPAddrFromKey(key)
        if src_ip in srcProcessedUDP:
            continue

        srcProcessedUDP.append(src_ip)
        writeUDPFlowsToFile(key, IpMapDict)

    for key in TCPFlows.keys():
        src_ip = getSrcIPAddrFromKey(key)
        if src_ip in srcProcessedTCP:
            continue

        srcProcessedTCP.append(src_ip)
        writeTCPFlowsToFile(key, IpMapDict)


def writeUDPFlowsToFile(write_key, IpMapDict = None):
    filename = getSrcIPAddrFromKey(write_key, True, IpMapDict) + "_UDP.ditg"
    written = False
    opened = False

    if os.path.isfile(filename):
        f = open(filename, 'a')
    else:
        f = open(filename, 'w')
        opened = True

    global first_time

    for key in UDPFlows.keys():
        if getSrcIPAddrFromKey(key) == getSrcIPAddrFromKey(write_key):
            # TODO : generate a file with IDTs instead
            timestamps = sorted(UDPFlows[key])
            sport = getSrcPortFromKey(key)
            dIP   = getDstIPAddrFromKey(key, True, IpMapDict)

            if dIP == '' or getSrcIPAddrFromKey(key, True, IpMapDict) == '':
                continue

            for time in timestamps:
                dport = getDstPort()
                s = '-z 1 -d ' + str((time - first_time) * 1000) + \
                    ' -rp ' + str(dport)   + \
                    ' -a '  + dIP + \
                    ' -c 800 ' + \
                    ' -T UDP' + '\n'
                f.write(s)
                written = True
    f.close()

    if opened and not written:
        os.remove(filename)

def writeTCPFlowsToFile(write_key, IpMapDict = None):
    filename = getSrcIPAddrFromKey(write_key, True, IpMapDict) + "_TCP.ditg"
    written = False
    opened = False

    if os.path.isfile(filename):
        f = open(filename, 'a')
    else:
        f = open(filename, 'w')
        opened = True

    global first_time

    for key in TCPFlows.keys():
        if getSrcIPAddrFromKey(key) == getSrcIPAddrFromKey(write_key):
            # TODO : generate a file with IDTs instead
            timestamps = sorted(TCPFlows[key])
            sport = getSrcPortFromKey(key)
            dIP   = getDstIPAddrFromKey(key, True, IpMapDict)

            if dIP == '' or getSrcIPAddrFromKey(key, True, IpMapDict) == '':
                continue

            for time in timestamps:
                dport = getDstPort()
                s = '-z 1 -d ' + str((time - first_time) * 1000) + \
                    ' -rp ' + str(dport)   + \
                    ' -a '  + dIP + \
                    ' -c 800' + \
                    ' -T TCP' + '\n'
                f.write(s)
                written = True
    f.close()

    if opened and not written:
        os.remove(filename)

def readPartitions(mapper_file):
    Partitions = {}
    i = 0
    with open(mapper_file, 'r') as f:
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

def generateMapper(list_file, mapper_file):
    IpMapDict = {}
    Partitions = readPartitions(mapper_file)

    i = 0
    for p in Partitions.keys():
        endPoints = Partitions[p]
        for i in range(int(endPoints[0]), int(endPoints[1]) + 1):
            print i
            ip = linecache.getline(list_file, i).strip().strip(',')
            IpMapDict[ip] = getIpForHost(p)

    return IpMapDict


def openAndReadPcap(filename, end_time):
    global first_time
    TCPFlows = {}
    UDPFlows = {}

    f = open(filename)
    pcap = dpkt.pcap.Reader(f)
    first = True
    i = 0
    for ts, buf in pcap:
        if first:
            first_time = ts
            first = False

        if first == False and (ts - first_time) >= end_time:
            break
        else:
            print (ts - first_time)

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
            key = getKey(inet_to_str(ip.src), TCP.sport, inet_to_str(ip.dst), TCP.dport)
            addToTCPFlow(TCPFlows, key, ts)
        elif ip.p == dpkt.ip.IP_PROTO_UDP: # Check for UDP packets
            UDP=ip.data
            key = getKey(inet_to_str(ip.src), UDP.sport, inet_to_str(ip.dst), UDP.dport)
            addToUDPFlow(UDPFlows, key, ts)
        else:
            # ignore other packets
            continue
        i += 1
    f.close()
    print "Total packets : " + str(i)

    return TCPFlows, UDPFlows

first_time = 0
end_time = 30

p = 12346

# IpMapDict = generateMapper('list.csv', 'mapper.csv')

IpMapDict = generateMapper('list.csv', 'mapper.csv')
TCPFlows, UDPFlows = openAndReadPcap('test2.pcap', end_time)
generateDITGFlowFiles(TCPFlows, UDPFlows, IpMapDict)
