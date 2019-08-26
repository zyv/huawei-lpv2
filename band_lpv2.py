import asyncio
import enum
import logging
import platform

from bleak import BleakClient

from huawei.services import DeviceConfig
from huawei.protocol import Packet, Command, TLV, hexlify, decode_int, NONCE_LENGTH, AUTH_VERSION, PROTOCOL_VERSION, \
    encode_int, digest_challenge, digest_response, create_bond_key

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("lpv2")

DEVICE_UUID = "A0E49DB2-XXXX-XXXX-XXXX-D75121192329"
DEVICE_MAC = "6C:B7:49:XX:XX:XX"

CLIENT_MAC = "C4:B3:01:XX:XX:XX"

GATT_WRITE = "0000fe01-0000-1000-8000-00805f9b34fb"
GATT_READ = "0000fe02-0000-1000-8000-00805f9b34fb"

CLIENT_SERIAL = b"X" * 6  # android.os.Build.SERIAL


class BandState(enum.Enum):
    Disconnected = enum.auto()
    Connected = enum.auto()
    RequestedLinkParams = enum.auto()
    ReceivedLinkParams = enum.auto()
    RequestedAuthentication = enum.auto()
    ReceivedAuthentication = enum.auto()
    RequestedBondParams = enum.auto()
    ReceivedBondParams = enum.auto()
    RequestedBond = enum.auto()
    ReceivedBond = enum.auto()


class Band:
    def __init__(self, client: BleakClient, mac_address, loop):
        self.client = client
        self.mac_address = mac_address
        self.loop = loop

        self.state = BandState.Disconnected

        self.protocol_version = None
        self.max_frame_size = None
        self.max_link_size = None
        self.connection_interval = None

        self.auth_version = None
        self.server_nonce = None
        self.client_nonce = None

        self.bond_status = None
        self.bond_status_info = None
        self.bt_version = None
        self.encryption_counter = None

        self._event = asyncio.Event()

    async def wait_for_state(self, state: BandState):
        logger.debug(f"Waiting for state: {state}...")
        await self._event.wait()
        if self.state != state:
            raise RuntimeError(f"bad state: {self.state} != {state}")
        logger.debug(f"Response received, state {state} attained!")

    def send_data(self, client: BleakClient, packet: Packet, requires_response: bool = True):
        data = bytes(packet)
        logger.debug(f"State: {self.state}, sending: {hexlify(data)}")

        if requires_response:
            self._event.clear()

        return client.write_gatt_char(GATT_WRITE, data)

    def receive_data(self, sender, data):
        logger.debug(f"State: {self.state}, received from '{sender}': {hexlify(bytes(data))}")
        packet = Packet.from_bytes(data)
        logger.debug(f"Parsed: {packet}")

        if self.state == BandState.RequestedLinkParams:
            if packet.service_id != DeviceConfig.id and packet.command_id != DeviceConfig.LinkParams.id:
                raise RuntimeError("unexpected packet")
            self.parse_link_params(packet.command)
        elif self.state == BandState.RequestedAuthentication:
            if packet.service_id != DeviceConfig.id and packet.command_id != DeviceConfig.Auth.id:
                raise RuntimeError("unexpected packet")
            self.parse_authentication(packet.command)
        elif self.state == BandState.RequestedBondParams:
            if packet.service_id != DeviceConfig.id and packet.command_id != DeviceConfig.BondParams.id:
                raise RuntimeError("unexpected packet")
            self.parse_bond_params(packet.command)
        elif self.state == BandState.RequestedBond:
            pass  # TODO: bonding

        self._event.set()

    async def connect(self):
        is_connected = await self.client.is_connected()

        if not is_connected:
            raise RuntimeError("device connection failed")

        self.state = BandState.Connected

        logger.info(f"State: {self.state}")

        await self.client.start_notify(GATT_READ, self.receive_data)

        await self.send_data(self.client, self.request_link_params())

        await self.wait_for_state(BandState.ReceivedLinkParams)

        await self.send_data(self.client, self.request_authentication())

        await self.wait_for_state(BandState.ReceivedAuthentication)

        await self.send_data(self.client, self.request_bond_params())

        await self.wait_for_state(BandState.ReceivedBondParams)

        # TODO: bonding

    async def disconnect(self):
        await self.client.stop_notify(GATT_READ)
        self.state = BandState.Disconnected

    def request_link_params(self) -> Packet:
        self.state = BandState.RequestedLinkParams
        return Packet(
            service_id=DeviceConfig.id,
            command_id=DeviceConfig.LinkParams.id,
            command=Command([
                TLV(DeviceConfig.LinkParams.Tags.ProtocolVersion),
                TLV(DeviceConfig.LinkParams.Tags.MaxFrameSize),
                TLV(DeviceConfig.LinkParams.Tags.MaxLinkSize),
                TLV(DeviceConfig.LinkParams.Tags.ConnectionInterval),
            ])
        )

    def parse_link_params(self, command: Command):
        if DeviceConfig.LinkParams.Tags.Error in command:
            raise RuntimeError("link parameter negotiation failed")

        self.protocol_version = decode_int(command[DeviceConfig.LinkParams.Tags.ProtocolVersion].value)
        self.max_frame_size = decode_int(command[DeviceConfig.LinkParams.Tags.MaxFrameSize].value)
        self.max_link_size = decode_int(command[DeviceConfig.LinkParams.Tags.MaxLinkSize].value)
        self.connection_interval = decode_int(command[DeviceConfig.LinkParams.Tags.ConnectionInterval].value)

        self.auth_version = decode_int(command[DeviceConfig.LinkParams.Tags.ServerNonce].value[:2])
        self.server_nonce = bytes(command[DeviceConfig.LinkParams.Tags.ServerNonce].value[2:18])

        # TODO: optional path extend number parsing

        if self.protocol_version != PROTOCOL_VERSION:
            raise RuntimeError(f"protocol version mismatch: {self.protocol_version} != {PROTOCOL_VERSION}")

        if self.auth_version != AUTH_VERSION:
            raise RuntimeError(f"authentication scheme version mismatch: {self.auth_version} != {AUTH_VERSION}")

        if len(self.server_nonce) != NONCE_LENGTH:
            raise RuntimeError(f"server nonce length mismatch: {len(self.server_nonce)} != {NONCE_LENGTH}")

        logger.info(
            f"Negotiated link parameters: "
            f"{self.protocol_version}, "
            f"{self.max_frame_size}, "
            f"{self.max_link_size}, "
            f"{self.connection_interval}, "
            f"{self.auth_version}, "
            f"{hexlify(self.server_nonce)}"
        )

        self.state = BandState.ReceivedLinkParams

    def request_authentication(self):
        self.client_nonce = b"X" * NONCE_LENGTH  # TODO: randomize

        packet = Packet(
            service_id=DeviceConfig.id,
            command_id=DeviceConfig.Auth.id,
            command=Command([
                TLV(tag=DeviceConfig.Auth.Tags.Challenge, value=digest_challenge(self.server_nonce, self.client_nonce)),
                TLV(tag=DeviceConfig.Auth.Tags.Nonce, value=(encode_int(self.auth_version) + self.client_nonce)),
            ])
        )

        self.state = BandState.RequestedAuthentication

        return packet

    def parse_authentication(self, command: Command):
        expected_answer = digest_response(self.server_nonce, self.client_nonce)
        provided_answer = command[DeviceConfig.Auth.Tags.Challenge].value

        if expected_answer != provided_answer:
            raise RuntimeError(f"wrong answer to provided challenge: {expected_answer} != {provided_answer}")

        self.state = BandState.ReceivedAuthentication

    def request_bond_params(self):
        packet = Packet(
            service_id=DeviceConfig.id,
            command_id=DeviceConfig.BondParams.id,
            command=Command(tlvs=[
                TLV(tag=DeviceConfig.BondParams.Tags.Status),
                TLV(tag=DeviceConfig.BondParams.Tags.Serial, value=CLIENT_SERIAL),
                TLV(tag=DeviceConfig.BondParams.Tags.BTVersion, value=b"\x02"),
                TLV(tag=DeviceConfig.BondParams.Tags.MaxFrameSize),
                TLV(tag=DeviceConfig.BondParams.Tags.ClientMacAddress, value=CLIENT_MAC.encode()),
                TLV(tag=DeviceConfig.BondParams.Tags.EncryptionCounter)
            ])
        )

        self.state = BandState.RequestedBondParams

        return packet

    def parse_bond_params(self, command: Command):
        if DeviceConfig.BondParams.Tags.Error in command:
            raise RuntimeError("bond parameter negotiation failed")

        self.bond_status = decode_int(command[DeviceConfig.BondParams.Tags.Status].value)
        self.bond_status_info = decode_int(command[DeviceConfig.BondParams.Tags.StatusInfo].value)
        self.bt_version = decode_int(command[DeviceConfig.BondParams.Tags.BTVersion].value)
        self.max_frame_size = decode_int(command[DeviceConfig.BondParams.Tags.MaxFrameSize].value)
        self.encryption_counter = decode_int(command[DeviceConfig.BondParams.Tags.EncryptionCounter].value)

        logger.info(
            f"Negotiated bond params: "
            f"{self.bond_status}, "
            f"{self.bond_status_info}, "
            f"{self.bt_version}, "
            f"{self.max_frame_size}, "
            f"{self.encryption_counter}"
        )

        self.state = BandState.ReceivedBondParams

    def request_bond(self):
        self.state = BandState.RequestedBond

    def parse_bond(self):
        if self.bond_status == 0:
            raise RuntimeError("bond params request rejected")

        self.state = BandState.ReceivedBond


async def run(loop):
    async with BleakClient(DEVICE_MAC if platform.system() != "Darwin" else DEVICE_UUID, loop=loop) as client:
        band = Band(client=client, mac_address=DEVICE_MAC, loop=loop)
        await band.connect()
        await band.disconnect()


event_loop = asyncio.get_event_loop()
event_loop.run_until_complete(run(event_loop))
