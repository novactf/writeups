from ast import parse
from binascii import *
from dataclasses import *
import hashlib
import base64
import pyshark


class MsgType:
    SESSION_INIT = 0
    ACK = 1
    CLIENT_KEY = 2
    SERVER_KEY = 3
    FILE_REQ = 4
    FILE_DATA = 5
    FIN = 6
    RETRANS = 7


@dataclass
class Msg:
    sid: int = 0
    payload: bytes = field(default_factory=list, repr=False)
    checksum: bytes = field(default_factory=list, repr=False)
    msg_type: int = 0

    @staticmethod
    def payload_checksum(payload: bytes) -> str:
        hasher = hashlib.sha1()
        hasher.update(payload)
        sha_payload = hasher.digest()
        b64_payload = base64.b64encode(sha_payload)
        return b64_payload[:-1][-8:]

    @staticmethod
    def calculate_shared_key(ckey: bytes, skey: bytes) -> str:
        combined = ckey + skey
        combined = [b for b in combined]
        combined.sort(reverse=True)
        hasher = hashlib.sha1()
        hasher.update(bytes(combined))
        sha_combined = hasher.digest()
        return base64.b64encode(sha_combined)

    @staticmethod
    def xor_crypt(payload: bytes, key: bytes) -> bytes:
        res = []
        for i in range(len(payload)):
            # WARN care with the b64 before/after
            res.append(payload[i] ^ key[i % len(key)])
        return bytes(res)

    @staticmethod
    def parse_session_init(pkt: bytes):
        sid = int.from_bytes(pkt[0:4], byteorder="big")
        payload = pkt[4:14]
        assert payload == b"newSession"
        recv_checksum = pkt[-8:]
        calc_checksum = Msg.payload_checksum(payload)
        assert recv_checksum == calc_checksum
        return Msg(sid, payload, recv_checksum, MsgType.SESSION_INIT)

    @staticmethod
    def parse_ack(pkt: bytes):
        sid = int.from_bytes(pkt[0:4], byteorder="big")
        if pkt[4:].startswith(b"sidAck"):
            payload = pkt[4:10]
        elif pkt[4:].startswith(b"fDataAck"):
            payload = pkt[4:12]
        elif pkt[4:].startswith(b"finAck"):
            payload = pkt[4:10]
        else:
            raise ValueError(f"unknown payload: {pkt[4:]}")
        assert payload == b"sidAck" or payload == b"fDataAck" or payload == b"finAck"
        # checksum = pkt[-8:]
        # assert checksum == Msg.payload_checksum(payload)
        return Msg(sid, payload, None, MsgType.ACK)

    @staticmethod
    def parse_client_key(pkt: bytes):
        sid = int.from_bytes(pkt[0:4], byteorder="big")
        payload = pkt[4 : 20]
        assert len(payload) == 16
        recv_checksum = pkt[22:30]
        calc_checksum = Msg.payload_checksum(payload)
        assert recv_checksum == calc_checksum
        return Msg(sid, payload, recv_checksum, MsgType.CLIENT_KEY)

    @staticmethod
    def parse_server_key(pkt: bytes):
        sid = int.from_bytes(pkt[0:4], byteorder="big")
        payload = pkt[4 : 20]
        assert len(payload) == 16
        recv_checksum = pkt[22:30]
        calc_checksum = Msg.payload_checksum(payload)
        assert recv_checksum == calc_checksum
        return Msg(sid, payload, calc_checksum, MsgType.SERVER_KEY)

    @staticmethod
    def parse_file_request(pkt: bytes):
        sid = int.from_bytes(pkt[0:4], byteorder="big")
        payload = pkt[4 : len(pkt) - 10]
        recv_checksum = pkt[-8:]
        calc_checksum = Msg.payload_checksum(payload)
        assert recv_checksum == calc_checksum
        return Msg(sid, payload, recv_checksum, MsgType.FILE_REQ)

    @staticmethod
    def parse_file_data(pkt: bytes):
        sid = int.from_bytes(pkt[0:4], byteorder="big")
        payload = pkt[5 : len(pkt) - 10]
        recv_checksum = pkt[-8:]
        calc_checksum = Msg.payload_checksum(payload)
        # print(payload[:16], recv_checksum, calc_checksum)
        # assert recv_checksum == calc_checksum
        return Msg(sid, payload, recv_checksum, MsgType.FILE_DATA)

    @staticmethod
    def parse_fin(pkt: bytes):
        sid = int.from_bytes(pkt[0:4], byteorder="big")
        payload = pkt[4 : len(pkt) - 10]
        checksum = pkt[-8:]
        assert checksum == Msg.payload_checksum(payload)
        return Msg(sid, payload, checksum, MsgType.FIN)

    @staticmethod
    def parse_packet(pkt: bytes):
        flag = pkt[-1]
        if flag == MsgType.SESSION_INIT or flag == 52:  # HACK because authors are dumb
            return Msg.parse_session_init(pkt)
        elif flag == MsgType.ACK:
            return Msg.parse_ack(pkt[:-2])
        elif flag == MsgType.CLIENT_KEY:
            return Msg.parse_client_key(pkt[:-2])
        elif flag == MsgType.SERVER_KEY:
            return Msg.parse_server_key(pkt[:-2])
        elif flag == MsgType.FILE_REQ:
            return Msg.parse_file_request(pkt[:-2])
        elif flag == MsgType.FILE_DATA:
            return Msg.parse_file_data(pkt[:-2])
        elif flag == MsgType.FIN:
            return Msg.parse_fin(pkt[:-2])
        elif flag == MsgType.RETRANS:
            pass


capture = pyshark.FileCapture(
    input_file="iftpp_challenge.pcap",
    keep_packets=True,
    display_filter="icmp",
)

parsed_messages = []

for packet in capture:
    pkt = unhexlify(packet.icmp.data)
    msg = Msg.parse_packet(pkt)
    print(msg)
    parsed_messages.append(msg)

shared_key = Msg.calculate_shared_key(parsed_messages[2].payload, parsed_messages[3].payload)

file_data = list(filter(lambda msg: msg.msg_type == MsgType.FILE_DATA, parsed_messages))

with open("out.jpg", "wb") as f:
    for data in file_data:
        f.write(Msg.xor_crypt(data.payload, shared_key))