from huawei.protocol import Packet, Command, TLV, digest_challenge, encode_int, AUTH_VERSION
from huawei.services import DeviceConfig


def request_link_params() -> Packet:
    return Packet(
        service_id=DeviceConfig.id,
        command_id=DeviceConfig.LinkParams.id,
        command=Command(tlvs=[
            TLV(DeviceConfig.LinkParams.Tags.ProtocolVersion),
            TLV(DeviceConfig.LinkParams.Tags.MaxFrameSize),
            TLV(DeviceConfig.LinkParams.Tags.MaxLinkSize),
            TLV(DeviceConfig.LinkParams.Tags.ConnectionInterval),
        ])
    )


def request_authentication(client_nonce: bytes, server_nonce: bytes) -> Packet:
    return Packet(
        service_id=DeviceConfig.id,
        command_id=DeviceConfig.Auth.id,
        command=Command(tlvs=[
            TLV(tag=DeviceConfig.Auth.Tags.Challenge, value=digest_challenge(server_nonce, client_nonce)),
            TLV(tag=DeviceConfig.Auth.Tags.Nonce, value=(encode_int(AUTH_VERSION) + client_nonce)),
        ])
    )


def request_bond_params(client_serial: str, client_mac: str):
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
        ])
    )
