import binascii
import hashlib
import hmac
import math

from typing import List

HUAWEI_LPV2_MAGIC = b"\x5A"

PROTOCOL_VERSION = 2
AUTH_VERSION = 1
NONCE_LENGTH = 16

NETWORK_BYTEORDER = "big"


def encode_int(value: int, length: int = 2) -> bytes:
    return value.to_bytes(length=length, byteorder=NETWORK_BYTEORDER)


def decode_int(data: bytes, signed: bool = False) -> int:
    return int.from_bytes(data, byteorder=NETWORK_BYTEORDER, signed=signed)


def hexlify(data: bytes) -> str:
    result = binascii.hexlify(data).upper()
    return " ".join(chr(odd) + chr(even) for odd, even in zip(result[::2], result[1::2]))


class VarInt:
    def __init__(self, value: int):
        if value < 0:
            raise ValueError("variable-length integer must be non-negative")
        self._value = value

    def __repr__(self):
        return f"VarInt({self._value})"

    def __eq__(self, other: "VarInt"):
        return self._value == other._value

    def __int__(self):
        return self._value

    def __len__(self):
        return math.ceil(math.log(self._value + 1, 2 ** 7)) if self._value > 2 else 1

    def __bytes__(self):
        data = []
        value = self._value
        while value >= 0:
            current_byte = value & 0b01111111
            data.append(current_byte | 0b10000000)
            if current_byte == value:
                data[0] &= 0b01111111
                return bytes(reversed(data))
            value >>= 7

    @staticmethod
    def from_bytes(data: bytes):
        value = 0
        for current_byte in data:
            value += current_byte & 0b01111111
            if not current_byte & 0b10000000:
                return VarInt(value)
            value <<= 7


class TLV:
    def __init__(self, tag: int, value: bytes = b""):
        self.tag = tag
        self.value = value

    def __repr__(self):
        return f"TLV(tag={self.tag}, value=b'{hexlify(self.value)}')"

    def __eq__(self, other: "TLV"):
        return (self.tag, self.value) == (other.tag, other.value)

    def __len__(self):
        return len(bytes(self))

    def __bytes__(self):
        return bytes([self.tag]) + bytes(VarInt(len(self.value))) + self.value

    @staticmethod
    def from_bytes(data: bytes):
        tag, body = data[0], data[1:]

        value_length = VarInt.from_bytes(body)
        value_begin, value_end = len(value_length), len(value_length) + int(value_length)

        return TLV(tag=tag, value=body[value_begin:value_end])


class Command:
    def __init__(self, tlvs: List[TLV] = None):
        self.tlvs = tlvs if tlvs is not None else []

    def __repr__(self):
        return f"Command(tlvs={self.tlvs})"

    def __eq__(self, other: "Command"):
        return self.tlvs == other.tlvs

    def __getitem__(self, tag: int):
        return next(filter(lambda item: item.tag == tag, self.tlvs))

    def __bytes__(self):
        return b"".join(map(bytes, self.tlvs))

    @staticmethod
    def from_bytes(data: bytes):
        tlvs = []
        while len(data):
            tlv = TLV.from_bytes(data)
            tlvs.append(tlv)
            data = data[len(tlv):]
        return Command(tlvs=tlvs)


class Packet:
    def __init__(self, service_id: int, command_id: int, command: Command):
        self.service_id = service_id
        self.command_id = command_id
        self.command = command

    def __repr__(self):
        return f"Packet(service_id={self.service_id}, command_id={self.command_id}, command={self.command})"

    def __eq__(self, other: "Packet"):
        return (self.service_id, self.command_id, self.command) == (other.service_id, other.command_id, other.command)

    def __bytes__(self) -> bytes:
        payload = bytes([self.service_id, self.command_id]) + bytes(self.command)

        if len(payload) > (2 ** 8) * 2:
            raise ValueError(f"payload too large: {len(payload)}")

        data = HUAWEI_LPV2_MAGIC + encode_int(len(payload) + 1) + b"\0" + payload

        return data + encode_int(binascii.crc_hqx(data, 0))

    @staticmethod
    def from_bytes(data: bytes) -> "Packet":

        if len(data) < 1 + 2 + 1 + 2:
            raise ValueError("packet too short")

        magic, length, padding, payload, checksum = data[0], data[1:2], data[3], data[4:-2], data[-2:]

        if magic != ord(HUAWEI_LPV2_MAGIC):
            raise ValueError(f"magic mismatch: {magic} != {HUAWEI_LPV2_MAGIC}")

        actual_checksum = encode_int(binascii.crc_hqx(data[:-2], 0))

        if actual_checksum != checksum:
            raise ValueError(f"checksum mismatch: {actual_checksum} != {checksum}")

        return Packet(service_id=payload[0], command_id=payload[1], command=Command.from_bytes(payload[2:]))


def compute_digest(message: str, server_nonce: bytes, client_nonce: bytes):
    prefix = "70FB6C24035FDB552F38898AEEDE3F69"
    nonce = server_nonce + client_nonce

    def digest(key: bytes, msg: bytes):
        return hmac.new(key, msg=msg, digestmod=hashlib.sha256).digest()

    return digest(digest(bytes.fromhex(prefix + message), nonce), nonce)


def digest_challenge(server_nonce: bytes, client_nonce: bytes):
    return compute_digest("0100", server_nonce, client_nonce)


def digest_response(server_nonce: bytes, client_nonce: bytes):
    return compute_digest("0110", server_nonce, client_nonce)
