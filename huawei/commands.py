from huawei.protocol import AUTH_VERSION, Command, Packet, TLV, create_bonding_key, digest_challenge, encode_int
from huawei.services import DeviceConfig, LocaleConfig


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


def request_authentication(client_nonce: bytes, server_nonce: bytes) -> Packet:
    return Packet(
        service_id=DeviceConfig.id,
        command_id=DeviceConfig.Auth.id,
        command=Command(tlvs=[
            TLV(tag=DeviceConfig.Auth.Tags.Challenge, value=digest_challenge(client_nonce, server_nonce)),
            TLV(tag=DeviceConfig.Auth.Tags.Nonce, value=(encode_int(AUTH_VERSION) + client_nonce)),
        ]),
    )


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


def request_set_time(timestamp: float, offset_hours: int, offset_minutes: int, key: bytes, iv: bytes) -> Packet:
    offset = encode_int(offset_hours, length=1) + encode_int(offset_minutes, length=1)

    return Packet(
        service_id=DeviceConfig.id,
        command_id=DeviceConfig.SetTime.id,
        command=Command(tlvs=[
            TLV(tag=DeviceConfig.SetTime.Tags.Timestamp, value=encode_int(int(timestamp), length=4)),
            TLV(tag=DeviceConfig.SetTime.Tags.ZoneOffset, value=offset),
        ]).encrypt(key, iv),
    )


def set_locale(language_tag: str, measurement_system: int, key: bytes, iv: bytes) -> Packet:
    return Packet(
        service_id=LocaleConfig.id,
        command_id=LocaleConfig.SetLocale.id,
        command=Command(tlvs=[
            TLV(tag=LocaleConfig.SetLocale.Tags.LanguageTag, value=language_tag.encode()),
            TLV(tag=LocaleConfig.SetLocale.Tags.MeasurementSystem, value=encode_int(measurement_system, length=1)),
        ]).encrypt(key, iv),
    )
