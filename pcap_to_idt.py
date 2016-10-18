#!/usr/bin/env python

import dpkt
import datetime
import socket
import linecache
import os

# Get Human-readable MAC addr
def mac_addr(address):
    """Convert a MAC address to a readable/printable string

       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    return ':'.join('%02x' % ord(b) for b in address)

# Get Human-readable IP addr
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


def getKey(src_ip, dst_ip):
    return src_ip + "_" + dst_ip

def getSrcIPAddrFromKey(key, mapped = False, IpMapDict = None):
    if mapped == False:
        return (key.split("_"))[0]
    elif IpMapDict != None:
        if key.split('_')[0] in IpMapDict.keys():
            return IpMapDict[key.split('_')[0]]

    return ''

def getDstIPAddrFromKey(key, mapped = False, IpMapDict = None):
    if mapped == False:
        return (key.split("_"))[1]
    elif IpMapDict != None:
        if key.split('_')[1] in IpMapDict.keys():
            return IpMapDict[key.split('_')[1]]

    return ''

def getDstPort():
    # Generates an un-reserved Port number
    global p

    if p == 12752:
        p = 12346
    else:
        p += 1

    return p

def addToFlows(Flows, key, timestamp, type='TCP'):
    if key in Flows.keys():
        l = Flows[key]
    else:
        l = []

    l.append(timestamp)
    Flows[key] = l

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

def getAllDistinctIPs(Flows):
    ipsProcessed = []
    for key in Flows.keys():
        origSIP = getSrcIPAddrFromKey(key)
        if origSIP not in ipsProcessed:
            ipsProcessed.append(origSIP)

        origDIP = getDstIPAddrFromKey(key)
        if origDIP not in ipsProcessed:
            ipsProcessed.append(origDIP)

    return ipsProcessed

def generateDITGFlowFiles(Flows, IpMapDict):
    i = 0
    for key in Flows.keys():
        i += 1
        print i
        writeFlowToFile(key, Flows, IpMapDict)


def writeFlowToFile(key, Flows, IpMapDict = None):
    origSIP = getSrcIPAddrFromKey(key)
    origDIP = getDstIPAddrFromKey(key)
    newSIP  = getSrcIPAddrFromKey(key, True, IpMapDict)
    newDIP  = getDstIPAddrFromKey(key, True, IpMapDict)

    if newDIP == '' or newSIP == '':
        print "R"
        return

    scriptFileName = newSIP + '.ditg'
    if os.path.exists(scriptFileName):
        f = open(scriptFileName, 'a')
    else:
        f = open(scriptFileName, 'w')

    idtsFileName = origSIP + '_' + origDIP + '.idts'
    idtsFile = open(idtsFileName, 'w')

    idts = Flows[key]
    for idt in idts:
        idtsFile.write(str(idt))
    idtsFile.close()

    f.write(
        '-z ' + str(len(idts)) + \
        ' -a ' + newDIP + \
        ' -rp '+ str(getDstPort()) + \
        ' -n 800 200 ' + \
        ' -Ft ' + idtsFileName + \
        ' -T TCP' + '\n'
    )

    f.close()

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
            ip = linecache.getline(list_file, i).strip().strip(',')
            IpMapDict[ip] = getIpForHost(p)

    return IpMapDict


def openAndReadPcap(filename, end_time):
    global first_time
    Flows = {}

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
            # print (ts - first_time)
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
            key = getKey(inet_to_str(ip.src), inet_to_str(ip.dst))

            addToFlows(Flows, key, (ts - first_time))
        elif ip.p == dpkt.ip.IP_PROTO_UDP: # Check for UDP packets
            UDP = ip.data
            key = getKey(inet_to_str(ip.src), inet_to_str(ip.dst))

            addToFlows(Flows, key, (ts - first_time), 'UDP')
        else:
            # ignore other packets
            continue
        i += 1

    f.close()
    print "Total packets : " + str(i)

    return Flows

first_time = 0
end_time = 30

os.system('rm *.ditg')
os.system('rm *.idts')

p = 12346

IpMapDict = generateMapper('list.csv', 'mapper.csv')
# print len(IpMapDict)
Flows = openAndReadPcap('test2.pcap', end_time)
# print len(Flows)
generateDITGFlowFiles(Flows, IpMapDict)

# ipsProcessed = getAllDistinctIPs(Flows)
# print ipsProcessed