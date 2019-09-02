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
