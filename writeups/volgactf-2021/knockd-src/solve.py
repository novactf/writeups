import pyshark
from mt19937predictor import MT19937Predictor

predictor = MT19937Predictor()

FILTER="ip.src == 192.168.0.105 and tcp.connection.syn and !(tcp.analysis.retransmission or tcp.analysis.fast_retransmission)"
cap = pyshark.FileCapture(input_file="/home/jmgd/Documents/volgactf/crypto/knock/knockd.pcap", keep_packets=True, display_filter=FILTER)

def join(a, b):
    return (a << 16) | b

def split(n):
    a = (n & (2 ** 32 - 2 ** 16)) >> 16
    b = n & (2 ** 16 - 1)
    return a, b

try:
    while True:
        p1 = int(cap.next().layers[2].dstport)
        p2 = int(cap.next().layers[2].dstport)
        cap.next()
        cap.next()
        cap.next()
        n = join(p1, p2)
        print(p1, p2, n)
        predictor.setrandbits(n, 32)
except StopIteration:
    _n = predictor.getrandbits(32)
    print(split(_n))