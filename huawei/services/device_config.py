from dataclasses import dataclass
from datetime import datetime
from enum import IntEnum, unique
from logging import getLogger
from typing import Tuple

from ..protocol import (
    NONCE_LENGTH,
    TLV,
    AuthVersion,
    Command,
    MismatchError,
    Packet,
    ProtocolVersion,
    check_result,
    create_bonding_key,
    decode_int,
    digest_challenge,
    digest_response,
    encode_int,
    encrypt_packet,
    hexlify,
    set_status,
)

logger = getLogger(__name__)


class DeviceConfig:
    id = 1

    class LinkParams:
        id = 1

        @unique
        class Tags(IntEnum):
            ProtocolVersion = 1
            MaxFrameSize = 2
            MaxLinkSize = 3
            ConnectionInterval = 4
            ServerNonce = 5
            PathExtendNumber = 6  # apparently used for BTVersion == 0

    class SetDateFormat:
        id = 4

        @unique
        class Tags(IntEnum):
            DateFormat = 2
            TimeFormat = 3
            SetDateFormat = 129

    class SetTime:
        id = 5

        @unique
        class Tags(IntEnum):
            Timestamp = 1
            ZoneOffset = 2

    class ProductInfo:
        id = 7

        @unique
        class Tags(IntEnum):
            BTVersion = 1
            ProductType = 2  # int
            HardwareVersion = 3
            PhoneNumber = 4
            MacAddress = 5
            IMEI = 6
            SoftwareVersion = 7
            OpenSourceVersion = 8
            SerialNumber = 9
            ProductModel = 10
            eMMCId = 11
            HealthAppSupport = 13  # int

    class Bond:
        id = 14

        @unique
        class Tags(IntEnum):
            BondRequest = 1
            Status = 2
            RequestCode = 3
            ClientSerial = 5
            BondingKey = 6
            InitVector = 7

    class BondParams:
        id = 15

        @unique
        class Tags(IntEnum):
            Status = 1
            StatusInfo = 2
            ClientSerial = 3
            BTVersion = 4
            MaxFrameSize = 5
            ClientMacAddress = 7
            EncryptionCounter = 9

    class Auth:
        id = 19

        @unique
        class Tags(IntEnum):
            Challenge = 1
            Nonce = 2

    class BatteryLevel:
        id = 8

        @unique
        class Tags(IntEnum):
            GetStatus = 1

    class ActivateOnRotate:
        id = 9

        @unique
        class Tags(IntEnum):
            SetStatus = 1

    class FactoryReset:
        id = 13

        @unique
        class Tags(IntEnum):
            SetStatus = 1

    class NavigateOnRotate:
        id = 27

        @unique
        class Tags(IntEnum):
            SetStatus = 1

    class LeftRightWrist:
        id = 26

        @unique
        class Tags(IntEnum):
            SetStatus = 1


def request_link_params() -> Packet:
    return Packet(
        service_id=DeviceConfig.id,
        command_id=DeviceConfig.LinkParams.id,
        command=Command(
            tlvs=[
                TLV(DeviceConfig.LinkParams.Tags.ProtocolVersion),
                TLV(DeviceConfig.LinkParams.Tags.MaxFrameSize),
                TLV(DeviceConfig.LinkParams.Tags.MaxLinkSize),
                TLV(DeviceConfig.LinkParams.Tags.ConnectionInterval),
            ],
        ),
    )


@dataclass
class LinkParams:
    protocol_version: ProtocolVersion
    max_frame_size: int
    max_link_size: int
    connection_interval: int  # milliseconds
    auth_version: AuthVersion


@check_result
def process_link_params(command: Command) -> Tuple[LinkParams, bytes]:
    link_params = LinkParams(
        protocol_version=ProtocolVersion(decode_int(command[DeviceConfig.LinkParams.Tags.ProtocolVersion].value)),
        max_frame_size=decode_int(command[DeviceConfig.LinkParams.Tags.MaxFrameSize].value),
        max_link_size=decode_int(command[DeviceConfig.LinkParams.Tags.MaxLinkSize].value),
        connection_interval=decode_int(command[DeviceConfig.LinkParams.Tags.ConnectionInterval].value),
        auth_version=AuthVersion(decode_int(command[DeviceConfig.LinkParams.Tags.ServerNonce].value[:2])),
    )

    server_nonce = bytes(command[DeviceConfig.LinkParams.Tags.ServerNonce].value[2:18])

    # TODO: optional path extend number parsing

    if link_params.protocol_version != ProtocolVersion.V2:
        raise MismatchError("protocol version", link_params.protocol_version, tuple(ProtocolVersion))

    if link_params.auth_version not in AuthVersion:
        raise MismatchError("authentication scheme version", link_params.auth_version, tuple(AuthVersion))

    if len(server_nonce) != NONCE_LENGTH:
        raise MismatchError("server nonce length", len(server_nonce), NONCE_LENGTH)

    logger.info(
        "Negotiated link parameters:\n\t%s",
        "\n\t".join(
            (
                f"Protocol version: {link_params.protocol_version}",
                f"Max frame size: {link_params.max_frame_size}",
                f"Max link size: {link_params.max_link_size}",
                f"Connection interval: {link_params.connection_interval}",
                f"Auth version : {link_params.auth_version}",
                f"Server nonce: {hexlify(server_nonce)}",
            ),
        ),
    )

    return link_params, server_nonce


def request_authentication(auth_version: AuthVersion, client_nonce: bytes, server_nonce: bytes) -> Packet:
    return Packet(
        service_id=DeviceConfig.id,
        command_id=DeviceConfig.Auth.id,
        command=Command(
            tlvs=[
                TLV(
                    tag=DeviceConfig.Auth.Tags.Challenge,
                    value=digest_challenge(auth_version, client_nonce, server_nonce),
                ),
                TLV(tag=DeviceConfig.Auth.Tags.Nonce, value=(encode_int(auth_version) + client_nonce)),
            ],
        ),
    )


@check_result
def process_authentication(auth_version: AuthVersion, command: Command, client_nonce: bytes, server_nonce: bytes):
    expected_answer = digest_response(auth_version, client_nonce, server_nonce)
    actual_answer = command[DeviceConfig.Auth.Tags.Challenge].value

    if expected_answer != actual_answer:
        raise MismatchError("challenge answer", actual_answer, expected_answer)

    logger.info("Process authentication:\n\tDone!")


def request_bond_params(client_serial: str, client_mac: str) -> Packet:
    return Packet(
        service_id=DeviceConfig.id,
        command_id=DeviceConfig.BondParams.id,
        command=Command(
            tlvs=[
                TLV(tag=DeviceConfig.BondParams.Tags.Status),
                TLV(tag=DeviceConfig.BondParams.Tags.ClientSerial, value=client_serial.encode()),
                TLV(tag=DeviceConfig.BondParams.Tags.BTVersion, value=b"\x02"),
                TLV(tag=DeviceConfig.BondParams.Tags.MaxFrameSize),
                TLV(tag=DeviceConfig.BondParams.Tags.ClientMacAddress, value=client_mac.encode()),
                TLV(tag=DeviceConfig.BondParams.Tags.EncryptionCounter),
            ],
        ),
    )


@check_result
def process_bond_params(command: Command) -> Tuple[int, int]:
    bond_status = decode_int(command[DeviceConfig.BondParams.Tags.Status].value)
    bond_status_info = decode_int(command[DeviceConfig.BondParams.Tags.StatusInfo].value)
    bt_version = decode_int(command[DeviceConfig.BondParams.Tags.BTVersion].value)
    max_frame_size = decode_int(command[DeviceConfig.BondParams.Tags.MaxFrameSize].value)
    encryption_counter = decode_int(command[DeviceConfig.BondParams.Tags.EncryptionCounter].value)

    # TODO: check bond status

    logger.info(
        "Negotiated bond params:\n\t%s",
        "\n\t".join(
            (
                f"Bond status: {bond_status}",
                f"Bond status info: {bond_status_info}",
                f"BT version: {bt_version}",
                f"Max frame size: {max_frame_size}",
                f"Encryption counter: {encryption_counter}",
            ),
        ),
    )

    return max_frame_size, encryption_counter


def request_bond(auth_version: AuthVersion, client_serial: str, device_mac: str, key: bytes, iv: bytes) -> Packet:
    return Packet(
        service_id=DeviceConfig.id,
        command_id=DeviceConfig.Bond.id,
        command=Command(
            tlvs=[
                TLV(tag=DeviceConfig.Bond.Tags.BondRequest),
                TLV(tag=DeviceConfig.Bond.Tags.RequestCode, value=b"\x00"),
                TLV(tag=DeviceConfig.Bond.Tags.ClientSerial, value=client_serial.encode()),
                TLV(tag=DeviceConfig.Bond.Tags.BondingKey, value=create_bonding_key(auth_version, device_mac, key, iv)),
                TLV(tag=DeviceConfig.Bond.Tags.InitVector, value=iv),
            ],
        ),
    )


@unique
class DateFormat(IntEnum):
    YearFirst = 1
    MonthFirst = 2
    DayFirst = 3


@unique
class TimeFormat(IntEnum):
    Hours12 = 1
    Hours24 = 2


@encrypt_packet
def set_date_format(date_format: DateFormat, time_format: TimeFormat) -> Packet:
    date_format_tlvs = [
        TLV(tag=DeviceConfig.SetDateFormat.Tags.DateFormat, value=encode_int(date_format.value, length=1)),
        TLV(tag=DeviceConfig.SetDateFormat.Tags.TimeFormat, value=encode_int(time_format.value, length=1)),
    ]
    return Packet(
        service_id=DeviceConfig.id,
        command_id=DeviceConfig.SetDateFormat.id,
        command=Command(
            tlvs=[
                TLV(tag=DeviceConfig.SetDateFormat.Tags.SetDateFormat, value=bytes(Command(tlvs=date_format_tlvs))),
            ],
        ),
    )


@encrypt_packet
def set_time(moment: datetime) -> Packet:
    def request_set_time(timestamp: float, zone_hours: int, zone_minutes: int) -> Packet:
        zone_offset = encode_int(zone_hours, length=1) + encode_int(zone_minutes, length=1)

        return Packet(
            service_id=DeviceConfig.id,
            command_id=DeviceConfig.SetTime.id,
            command=Command(
                tlvs=[
                    TLV(tag=DeviceConfig.SetTime.Tags.Timestamp, value=encode_int(int(timestamp), length=4)),
                    TLV(tag=DeviceConfig.SetTime.Tags.ZoneOffset, value=zone_offset),
                ],
            ),
        )

    offset = (moment - datetime.utcfromtimestamp(moment.timestamp())).total_seconds() / 3600
    float_hours, float_minutes = divmod(offset, 1)

    offset_hours = int(abs(float_hours) + 128) if float_hours < 0 else int(float_hours)
    offset_minutes = int(abs(float_minutes * 60))

    return request_set_time(moment.timestamp(), offset_hours, offset_minutes)


@encrypt_packet
def set_activate_on_rotate(state: bool) -> Packet:
    return set_status(
        DeviceConfig.id,
        DeviceConfig.ActivateOnRotate.id,
        DeviceConfig.ActivateOnRotate.Tags.SetStatus,
        state,
    )


@encrypt_packet
def set_navigate_on_rotate(state: bool) -> Packet:
    return set_status(
        DeviceConfig.id,
        DeviceConfig.NavigateOnRotate.id,
        DeviceConfig.NavigateOnRotate.Tags.SetStatus,
        state,
    )


@encrypt_packet
def request_battery_level() -> Packet:
    return Packet(
        service_id=DeviceConfig.id,
        command_id=DeviceConfig.BatteryLevel.id,
        command=Command(
            tlvs=[
                TLV(tag=DeviceConfig.BatteryLevel.Tags.GetStatus),
            ],
        ),
    )


@check_result
def process_battery_level(command: Command):
    return decode_int(command[DeviceConfig.BatteryLevel.Tags.GetStatus].value)


@encrypt_packet
def set_right_wrist(state: bool) -> Packet:
    return set_status(
        DeviceConfig.id,
        DeviceConfig.LeftRightWrist.id,
        DeviceConfig.LeftRightWrist.Tags.SetStatus,
        state,
    )


@encrypt_packet
def factory_reset() -> Packet:
    return set_status(
        DeviceConfig.id,
        DeviceConfig.FactoryReset.id,
        DeviceConfig.FactoryReset.Tags.SetStatus,
        True,
    )


@encrypt_packet
def request_product_info() -> Packet:
    return Packet(
        service_id=DeviceConfig.id,
        command_id=DeviceConfig.ProductInfo.id,
        command=Command(tlvs=[TLV(tag=i) for i in range(14)]),
    )
