import asyncio
import binascii
import enum
import hashlib
import hmac
import math
import secrets
from functools import wraps
from logging import getLogger
from typing import Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .services import RESULT_SUCCESS, TAG_RESULT, CryptoTags

logger = getLogger(__name__)


@enum.unique
class ProtocolVersion(enum.IntEnum):
    V2 = 2


@enum.unique
class AuthVersion(enum.IntEnum):
    V1 = 1
    V2 = 2
    V3 = 3


HUAWEI_LPV2_MAGIC = b"\x5A"

NETWORK_BYTEORDER = "big"

DIGEST_SECRETS = {
    AuthVersion.V1: "70 FB 6C 24 03 5F DB 55 2F 38 89 8A EE DE 3F 69",
    AuthVersion.V2: "93 AC DE F7 6A CB 09 85 7D BF E5 26 1A AB CD 78",
    AuthVersion.V3: "9C 27 63 A9 CC E1 34 76 6D E3 FF 61 18 20 05 53",
}

MESSAGE_RESPONSE = "0110"
MESSAGE_CHALLENGE = "0100"

SECRET_KEYS = {
    AuthVersion.V1: (
        "6F 75 6A 79 6D 77 71 34 63 6C 76 39 33 37 38 79",
        "62 31 30 6A 67 66 64 39 79 37 76 73 75 64 61 39",
    ),
    AuthVersion.V2: (
        "55 53 86 FC 63 20 07 AA 86 49 35 22 B8 6A E2 5C",
        "33 07 9B C5 7A 88 6D 3C F5 61 37 09 6F 22 80 00",
    ),
    AuthVersion.V3: (
        "55 53 86 FC 63 20 07 AA 86 49 35 22 B8 6A E2 5C",
        "33 07 9B C5 7A 88 6D 3C F5 61 37 09 6F 22 80 00",
    ),
}

AES_KEY_SIZE = 16
NONCE_LENGTH = 16

ENCRYPTION_COUNTER_MAX = 4294967295

GATT_WRITE = "0000fe01-0000-1000-8000-00805f9b34fb"
GATT_READ = "0000fe02-0000-1000-8000-00805f9b34fb"


class ProtocolError(Exception):
    pass


class MismatchError(ProtocolError, ValueError):
    def __init__(self, entity, actual, expected):
        super().__init__(f"{entity} mismatch: {actual} != {expected}")


def encode_int(value: int, length: int = 2) -> bytes:
    return value.to_bytes(length=length, byteorder=NETWORK_BYTEORDER)


def decode_int(data: bytes, signed: bool = False) -> int:
    return int.from_bytes(data, byteorder=NETWORK_BYTEORDER, signed=signed)


def hexlify(data: bytes) -> str:
    result = binascii.hexlify(data).upper()
    return " ".join(chr(odd) + chr(even) for odd, even in zip(result[::2], result[1::2]))


def initialization_vector(counter: int) -> (int, bytes):
    if counter == ENCRYPTION_COUNTER_MAX:
        counter = 1
    else:
        counter += 1
    return counter, generate_nonce()[:-4] + encode_int(counter, length=4)


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
        return math.ceil(math.log(self._value + 1, 2**7)) if self._value > 2 else 1

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
        value = f"bytes({self.command})" if self.command is not None else f"bytes.fromhex('{hexlify(self.value)}')"
        return f"TLV(tag={self.tag}, value={value})"

    def __eq__(self, other: "TLV"):
        return (self.tag, self.value) == (other.tag, other.value)

    def __len__(self):
        return len(bytes(self))

    def __bytes__(self):
        return bytes([self.tag]) + bytes(VarInt(len(self.value))) + self.value

    @property
    def command(self) -> Optional["Command"]:
        return Command.from_bytes(self.value) if self.tag & 0b10000000 else None

    @staticmethod
    def from_bytes(data: bytes):
        tag, body = data[0], data[1:]

        value_length = VarInt.from_bytes(body)
        value_begin, value_end = len(value_length), len(value_length) + int(value_length)

        return TLV(tag=tag, value=body[value_begin:value_end])


class Command:
    def __init__(self, tlvs: list[TLV] = None):
        self.tlvs = tlvs if tlvs is not None else []

    def __repr__(self):
        return f"Command(tlvs={self.tlvs})"

    def __eq__(self, other: "Command"):
        return self.tlvs == other.tlvs

    def __contains__(self, tag: int):
        return any(item.tag == tag for item in self.tlvs)

    def __getitem__(self, tag: int):
        return next(filter(lambda item: item.tag == tag, self.tlvs))

    def __bytes__(self):
        return b"".join(map(bytes, self.tlvs))

    def encrypt(self, key: bytes, iv: bytes) -> "Command":
        return Command(
            tlvs=[
                TLV(tag=CryptoTags.Encryption, value=b"\x01"),
                TLV(tag=CryptoTags.InitVector, value=iv),
                TLV(tag=CryptoTags.CipherText, value=encrypt(bytes(self), key, iv)),
            ],
        )

    def decrypt(self, key: bytes, iv: bytes) -> "Command":
        return Command.from_bytes(decrypt(self[CryptoTags.CipherText].value, key, iv))

    @staticmethod
    def from_bytes(data: bytes):
        tlvs = []
        while len(data):
            tlv = TLV.from_bytes(data)
            tlvs.append(tlv)
            data = data[len(tlv) :]
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

        maximum_payload_length = 2 ** (8 * 2)
        if len(payload) > maximum_payload_length:
            raise MismatchError("payload length", len(payload), maximum_payload_length)

        data = HUAWEI_LPV2_MAGIC + encode_int(len(payload) + 1) + b"\0" + payload

        return data + encode_int(binascii.crc_hqx(data, 0))

    @staticmethod
    def from_bytes(data: bytes) -> "Packet":

        minimum_length = 1 + 2 + 1 + 2
        if len(data) < minimum_length:
            raise MismatchError("packet length", len(data), minimum_length)

        magic, _, payload, expected_checksum = data[0], data[1:3], data[4:-2], data[-2:]

        if magic != ord(HUAWEI_LPV2_MAGIC):
            raise MismatchError("magic", magic, HUAWEI_LPV2_MAGIC)

        actual_checksum = encode_int(binascii.crc_hqx(data[:-2], 0))

        if actual_checksum != expected_checksum:
            raise MismatchError("checksum", actual_checksum, expected_checksum)

        return Packet(service_id=payload[0], command_id=payload[1], command=Command.from_bytes(payload[2:]))

    def encrypt(self, key: bytes, iv: bytes) -> "Packet":
        return Packet(service_id=self.service_id, command_id=self.command_id, command=self.command.encrypt(key, iv))

    def decrypt(self, key: bytes, iv: bytes) -> "Packet":
        return Packet(service_id=self.service_id, command_id=self.command_id, command=self.command.decrypt(key, iv))


def encrypt_packet(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not all(arg in kwargs for arg in ("key", "iv")):
            raise TypeError("encrypt_packet expects 'key' and 'iv' arguments")
        key, iv = kwargs.pop("key"), kwargs.pop("iv")
        return func(*args, **kwargs).encrypt(key, iv)

    return wrapper


def process_result(command: Command) -> Optional[int]:
    if TAG_RESULT in command:
        return decode_int(command[TAG_RESULT].value)


def check_result(func):
    def raise_if_unsuccessful(command: Command):
        result = process_result(command)
        if result is not None and result != RESULT_SUCCESS:
            raise MismatchError("result code", result, RESULT_SUCCESS)

    if asyncio.iscoroutinefunction(func):

        @wraps(func)
        async def wrapper(*args, **kwargs):
            command = await func(*args, **kwargs)
            logger.debug(f"Checking coroutine result: {command}...")
            raise_if_unsuccessful(command)
            return command

        return wrapper
    else:

        @wraps(func)
        def wrapper(*args, **kwargs):
            command = args[0] if isinstance(args[0], Command) else args[1]  # support bound methods
            logger.debug(f"Checking function or bound method input: {command}...")
            assert isinstance(command, Command)
            raise_if_unsuccessful(command)
            return func(*args, **kwargs)

        return wrapper


def set_status(service_id: int, command_id: int, tag: int, value: bool) -> Packet:
    return Packet(
        service_id=service_id,
        command_id=command_id,
        command=Command(
            tlvs=[
                TLV(tag=tag, value=encode_int(int(value), length=1)),
            ],
        ),
    )


def compute_digest(auth_version: AuthVersion, message: str, client_nonce: bytes, server_nonce: bytes):
    complete_nonce = server_nonce + client_nonce

    def digest(key: bytes, msg: bytes):
        return hmac.new(key, msg=msg, digestmod=hashlib.sha256).digest()

    return digest(digest(bytes.fromhex(DIGEST_SECRETS[auth_version] + message), complete_nonce), complete_nonce)


def digest_challenge(auth_version: AuthVersion, client_nonce: bytes, server_nonce: bytes):
    return compute_digest(auth_version, MESSAGE_RESPONSE, client_nonce, server_nonce)


def digest_response(auth_version: AuthVersion, client_nonce: bytes, server_nonce: bytes):
    return compute_digest(auth_version, MESSAGE_RESPONSE, client_nonce, server_nonce)


def generate_nonce() -> bytes:
    return secrets.token_bytes(NONCE_LENGTH)


def encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    padder = padding.PKCS7(8 * AES_KEY_SIZE).padder()
    padded_data = padder.update(data) + padder.finalize()

    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()

    return encryptor.update(padded_data) + encryptor.finalize()


def decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(data) + decryptor.finalize()

    unpadder = padding.PKCS7(8 * AES_KEY_SIZE).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()


def create_secret_key(auth_version: AuthVersion, mac_address: str) -> bytes:
    mac_address_key = (mac_address.replace(":", "") + "0000").encode()

    left_key, right_key = map(bytes.fromhex, SECRET_KEYS[auth_version])

    mixed_secret_key = (
        ((left_key_byte << 4) ^ right_key_byte) & 0xFF for left_key_byte, right_key_byte in zip(left_key, right_key)
    )

    mixed_secret_key_hash = hashlib.sha256(bytes(mixed_secret_key)).digest()

    final_mixed_key = (
        ((mixed_secret_key_hash_byte >> 6) ^ mac_address_byte) & 0xFF
        for mixed_secret_key_hash_byte, mac_address_byte in zip(mixed_secret_key_hash, mac_address_key)
    )

    return hashlib.sha256(bytes(final_mixed_key)).digest()[:AES_KEY_SIZE]


def create_bonding_key(auth_version: AuthVersion, mac_address: str, key: bytes, iv: bytes) -> bytes:
    return encrypt(key, create_secret_key(auth_version, mac_address), iv)
