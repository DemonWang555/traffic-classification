import binascii
from configparser import ConfigParser
from threading import Thread, Lock

import numpy
import tensorflow as tf
from grpc.beta import implementations
from tensorflow_serving.apis import prediction_service_pb2, predict_pb2

import socket
import struct
# import pymysql
import datetime

dict_10class_malware = {0: 'Cridex', 1: 'Geodo', 2: 'Htbot', 3: 'Miuref', 4: 'Neris', 5: 'Nsis-ay', 6: 'Shifu',
                        7: 'Tinba', 8: 'Virut', 9: 'Zeus'}
dict_20class = {0: 'BitTorrent', 1: 'Facetime', 2: 'FTP', 3: 'Gmail', 4: 'MySQL', 5: 'Outlook', 6: 'Skype', 7: 'SMB', 8: 'We
ibo', 9: 'WorldOfWarcraft',
                10: 'Cridex', 11: 'Geodo', 12: 'Htbot', 13: 'Miuref', 14: 'Neris', 15: 'Nsis-ay', 16: 'Shifu', 17: 'Tinba', 
18: 'Virut', 19: 'Zeus'}

# 配置文件读取接口
conf = ConfigParser()
conf.read(filenames='traffic.cfg', encoding='UTF-8')

# gRPC通道
channel = implementations.insecure_channel(
    conf['grpc']['host'], conf.getint('grpc', 'port'))
stub = prediction_service_pb2.beta_create_PredictionService_stub(channel)

lock = Lock()

# 创建Socket，SOCK_DGRAM指定了这个Socket的类型是TCP
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('', conf.getint('socket_server', 'port')))
s.listen(128)


def getMatrixfrom_pcap(data):
    # 读取二进制
    hexst = binascii.hexlify(data)
    fh = numpy.array([int(hexst[i:i + 2], 16)
                     for i in range(0, len(hexst), 2)])

    new_fh = numpy.uint8(fh)
    if fh.size > 784:
        new_fh = fh[0:784]

    return new_fh


def doGrpc(data):
    fn = getMatrixfrom_pcap(data)

    request = predict_pb2.PredictRequest()

    # 指定启动tensorflow serving时配置的model_name和是保存模型时的方法名
    request.model_spec.name = "traffic"
    request.model_spec.signature_name = "predict_images"

    # 指定输入
    request.inputs["images"].CopyFrom(
        tf.contrib.util.make_tensor_proto(fn.tolist(), shape=[1, 784], dtype=tf.float32))
    request.inputs["keep_prob"].CopyFrom(
        tf.contrib.util.make_tensor_proto(1.0, dtype=tf.float32))

    response = stub.Predict(request, 10.0)  # 10 secs timeout

    # 从response中获取分类结果
    results = {}
    for key in response.outputs:
        tensor_proto = response.outputs[key]
        results[key] = tf.contrib.util.make_ndarray(tensor_proto)

    score = results["scores"][0]
    # type = dict_10class_malware[score]
    type = dict_20class[score]

    return score
  

def do(sock, addr):
    try:
        while True:
            # 接收TCP消息头，并检测
            head_buf = sock.recv(16)
            if not head_buf:
                print('客户端{}已断开！'.format(addr))
                break
            proto_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
            saddr, daddr, sport, dport, proto, code, bytes = struct.unpack('!IIHHBBH', head_buf[0:16])

            def toIp(x): return '.'.join([str(x // (256 ** i) % 256) for i in range(3, -1, -1)])  # 通过整数获取ip
            saddr_str = toIp(saddr)
            daddr_str = toIp(daddr)

            # 接收消息体
            body_buf = sock.recv(bytes)
            # if len(body_buf) != 784:
            #     continue
            format_str = "!" + str(bytes) + "s"
            data = struct.unpack(format_str, body_buf)[0]

            # 检测并将结果回传
            type = doGrpc(data)
            if type < 10:
              classes = 0
            else：
              classes = 1
            fname = {"srcIP": saddr_str, "dstIP": daddr_str, "proto": proto_str, "srcPort": str(sport), "dstPort": str(dport), "class": str(classes)}
            sock.send(fname.encode('utf-8'))  # 需要根据控制平面的具体情况重新建立socket连接
    finally:
        sock.close()


def main():
    try:
        while True:
            hostname = socket.gethostname()
            # 获取本机ip
            ip = socket.gethostbyname(hostname)
            print('服务器正在 ' + ip + ':' +
                  conf['socket_server']['port'] + ' 运行，等待客户端连接...')
            sock, addr = s.accept()
            print('客户端{}已连接！'.format(addr))
            # do(sock, addr)
            p = Thread(target=do, args=(sock, addr))
            p.start()

    finally:
        # 关闭监听socket，不再响应其它客户端连接
        s.close()


if __name__ == '__main__':
    main()
