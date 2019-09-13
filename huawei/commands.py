from dataclasses import dataclass
from datetime import datetime
from logging import getLogger
from typing import Tuple

from huawei.protocol import AUTH_VERSION, Command, NONCE_LENGTH, PROTOCOL_VERSION, Packet, TLV, create_bonding_key, \
    decode_int, digest_challenge, digest_response, encode_int, hexlify
from huawei.services import DeviceConfig, LocaleConfig, TAG_RESULT

logger = getLogger(__name__)


def request_link_params() -> Packet:
    return Packet(
        service_id=DeviceConfig.id,
        command_id=DeviceConfig.LinkParams.id,
        command=Command(tlvs=[
            TLV(DeviceConfig.LinkParams.Tags.ProtocolVersion),
            TLV(DeviceConfig.LinkParams.Tags.MaxFrameSize),
            TLV(DeviceConfig.LinkParams.Tags.MaxLinkSize),
            TLV(DeviceConfig.LinkParams.Tags.ConnectionInterval),
        ]),
    )


@dataclass
class LinkParams:
    max_frame_size: int
    max_link_size: int
    connection_interval: int  # milliseconds


def process_link_params(command: Command) -> Tuple[LinkParams, bytes]:
    if TAG_RESULT in command:
        raise RuntimeError("link parameter negotiation failed")

    link_params = LinkParams(
        max_frame_size=decode_int(command[DeviceConfig.LinkParams.Tags.MaxFrameSize].value),
        max_link_size=decode_int(command[DeviceConfig.LinkParams.Tags.MaxLinkSize].value),
        connection_interval=decode_int(command[DeviceConfig.LinkParams.Tags.ConnectionInterval].value),
    )

    protocol_version = decode_int(command[DeviceConfig.LinkParams.Tags.ProtocolVersion].value)
    auth_version = decode_int(command[DeviceConfig.LinkParams.Tags.ServerNonce].value[:2])
    server_nonce = bytes(command[DeviceConfig.LinkParams.Tags.ServerNonce].value[2:18])

    # TODO: optional path extend number parsing

    if protocol_version != PROTOCOL_VERSION:
        raise RuntimeError(f"protocol version mismatch: {protocol_version} != {PROTOCOL_VERSION}")

    if auth_version != AUTH_VERSION:
        raise RuntimeError(f"authentication scheme version mismatch: {auth_version} != {AUTH_VERSION}")

    if len(server_nonce) != NONCE_LENGTH:
        raise RuntimeError(f"server nonce length mismatch: {len(server_nonce)} != {NONCE_LENGTH}")

    logger.info(
        f"Negotiated link parameters: "
        f"{link_params.max_frame_size}, "
        f"{link_params.max_link_size}, "
        f"{link_params.connection_interval}, "
        f"{hexlify(server_nonce)}",
    )

    return link_params, server_nonce


def request_authentication(client_nonce: bytes, server_nonce: bytes) -> Packet:
    return Packet(
        service_id=DeviceConfig.id,
        command_id=DeviceConfig.Auth.id,
        command=Command(tlvs=[
            TLV(tag=DeviceConfig.Auth.Tags.Challenge, value=digest_challenge(client_nonce, server_nonce)),
            TLV(tag=DeviceConfig.Auth.Tags.Nonce, value=(encode_int(AUTH_VERSION) + client_nonce)),
        ]),
    )


def process_authentication(client_nonce: bytes, server_nonce: bytes, command: Command):
    expected_answer = digest_response(client_nonce, server_nonce)
    provided_answer = command[DeviceConfig.Auth.Tags.Challenge].value

    if expected_answer != provided_answer:
        raise RuntimeError(f"wrong answer to provided challenge: {expected_answer} != {provided_answer}")


def request_bond_params(client_serial: str, client_mac: str) -> Packet:
    return Packet(
        service_id=DeviceConfig.id,
        command_id=DeviceConfig.BondParams.id,
        command=Command(tlvs=[
            TLV(tag=DeviceConfig.BondParams.Tags.Status),
            TLV(tag=DeviceConfig.BondParams.Tags.ClientSerial, value=client_serial.encode()),
            TLV(tag=DeviceConfig.BondParams.Tags.BTVersion, value=b"\x02"),
            TLV(tag=DeviceConfig.BondParams.Tags.MaxFrameSize),
            TLV(tag=DeviceConfig.BondParams.Tags.ClientMacAddress, value=client_mac.encode()),
            TLV(tag=DeviceConfig.BondParams.Tags.EncryptionCounter),
        ]),
    )


def request_bond(client_serial: str, device_mac: str, key: bytes, iv: bytes) -> Packet:
    return Packet(
        service_id=DeviceConfig.id,
        command_id=DeviceConfig.Bond.id,
        command=Command(tlvs=[
            TLV(tag=DeviceConfig.Bond.Tags.BondRequest),
            TLV(tag=DeviceConfig.Bond.Tags.RequestCode, value=b"\x00"),
            TLV(tag=DeviceConfig.Bond.Tags.ClientSerial, value=client_serial.encode()),
            TLV(tag=DeviceConfig.Bond.Tags.BondingKey, value=create_bonding_key(device_mac, key, iv)),
            TLV(tag=DeviceConfig.Bond.Tags.InitVector, value=iv),
        ]),
    )


def process_bond_params(command: Command) -> Tuple[int, int]:
    if TAG_RESULT in command:
        raise RuntimeError("bond parameter negotiation failed")

    bond_status = decode_int(command[DeviceConfig.BondParams.Tags.Status].value)
    bond_status_info = decode_int(command[DeviceConfig.BondParams.Tags.StatusInfo].value)
    bt_version = decode_int(command[DeviceConfig.BondParams.Tags.BTVersion].value)
    max_frame_size = decode_int(command[DeviceConfig.BondParams.Tags.MaxFrameSize].value)
    encryption_counter = decode_int(command[DeviceConfig.BondParams.Tags.EncryptionCounter].value)

    # TODO: check bond status

    logger.info(
        f"Negotiated bond params: "
        f"{bond_status}, "
        f"{bond_status_info}, "
        f"{bt_version}, "
        f"{max_frame_size}, "
        f"{encryption_counter}",
    )

    return max_frame_size, encryption_counter


def set_time(moment: datetime, key: bytes, iv: bytes) -> Packet:
    def request_set_time(timestamp: float, zone_hours: int, zone_minutes: int, key: bytes, iv: bytes) -> Packet:
        zone_offset = encode_int(zone_hours, length=1) + encode_int(zone_minutes, length=1)

        return Packet(
            service_id=DeviceConfig.id,
            command_id=DeviceConfig.SetTime.id,
            command=Command(tlvs=[
                TLV(tag=DeviceConfig.SetTime.Tags.Timestamp, value=encode_int(int(timestamp), length=4)),
                TLV(tag=DeviceConfig.SetTime.Tags.ZoneOffset, value=zone_offset),
            ]).encrypt(key, iv),
        )

    offset = (moment - datetime.utcfromtimestamp(moment.timestamp())).total_seconds() / 3600
    float_hours, float_minutes = divmod(offset, 1)

    offset_hours = int(abs(float_hours) + 128) if float_hours < 0 else int(float_hours)
    offset_minutes = int(abs(float_minutes * 60))

    return request_set_time(moment.timestamp(), offset_hours, offset_minutes, key, iv)


def set_locale(language_tag: str, measurement_system: int, key: bytes, iv: bytes) -> Packet:
    return Packet(
        service_id=LocaleConfig.id,
        command_id=LocaleConfig.SetLocale.id,
        command=Command(tlvs=[
            TLV(tag=LocaleConfig.SetLocale.Tags.LanguageTag, value=language_tag.encode()),
            TLV(tag=LocaleConfig.SetLocale.Tags.MeasurementSystem, value=encode_int(measurement_system, length=1)),
        ]).encrypt(key, iv),
    )
