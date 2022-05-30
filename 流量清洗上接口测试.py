import socket
import struct
import binascii
from configparser import ConfigParser
from threading import Thread, Lock

import numpy



def getMatrixfrom_pcap(data):
    # 读取二进制
    hexst = binascii.hexlify(data)
    fh = numpy.array([int(hexst[i:i + 2], 16)
                     for i in range(0, len(hexst), 2)])

    new_fh = numpy.uint8(fh)
    if fh.size > 784:
        new_fh = fh[0:784]

    return new_fh

c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_ip = '127.0.0.1'
server_port = 9999

# c.connect((server_ip, server_port))

saddr = 175727897
daddr = 175727897
sport = 45323
dport = 1200
proto = 6
code = 1
bytes = 784
message = b'6' * 784

data = struct.pack('!IIHHBBH', saddr, daddr, sport, dport, proto, code, bytes)
print(data)
send_data = struct.pack('!IIHHBBH784s', saddr, daddr, sport, dport, proto, code, bytes, message)
print(len(send_data))
print(send_data)

c.connect((server_ip, server_port))
c.send(send_data)
print('数据发送完成！')

data = c.recv(1024)
print(data.decode('utf-8'))
# data = c.recv(1024)
print(json.loads(data))
# saddr, daddr, sport, dport, proto = struct.unpack('!IIHHB', data[0:13])

# print(send_data, len(send_data))
# saddr, daddr, sport, dport, proto, code, bytes, data = struct.unpack('!IIHHBBH784s', send_data)

# toIp = lambda x: '.'.join([str(x // (256 ** i) % 256) for i in range(3, -1, -1)])  # 通过整数获取ip
# saddr_str = toIp(saddr)
# daddr_str = toIp(daddr)
# print(saddr_str, daddr_str, sport, dport, proto)
# print(data)

c.close()
