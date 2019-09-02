import asyncio
import base64
import enum
import logging
import platform
import time

from configparser import ConfigParser
from pathlib import Path

from bleak import BleakClient

from huawei.services import DeviceConfig, TAG_ERROR
from huawei.protocol import Packet, Command, TLV, hexlify, decode_int, NONCE_LENGTH, AUTH_VERSION, PROTOCOL_VERSION, \
    encode_int, digest_challenge, digest_response, create_bonding_key, generate_nonce

DEVICE_NAME = "default"

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("lpv2")

CONFIG_FILE = Path("band.ini")

GATT_WRITE = "0000fe01-0000-1000-8000-00805f9b34fb"
GATT_READ = "0000fe02-0000-1000-8000-00805f9b34fb"


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
    def __init__(self, client: BleakClient, client_mac: str, device_mac: str, secret: bytes, loop):
        self.state = BandState.Disconnected

        self.client = client
        self.client_mac = client_mac
        self.device_mac = device_mac
        self.secret = secret
        self.loop = loop

        self.client_serial = client_mac.replace(":", "").encode()[-6:]  # android.os.Build.SERIAL

        self.protocol_version = 2
        self.max_frame_size = 254
        self.max_link_size = 254
        self.connection_interval = 10  # milliseconds

        self.auth_version = 1
        self.server_nonce = None
        self.client_nonce = generate_nonce()

        self.bond_status = None
        self.bond_status_info = None
        self.bt_version = None
        self.encryption_counter = 0

        self._event = asyncio.Event()

    def _next_iv(self):
        self.encryption_counter += 1  # TODO: overflow
        return generate_nonce()[:-4] + encode_int(self.encryption_counter, length=4)

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
            if packet.service_id != DeviceConfig.id and packet.command_id != DeviceConfig.Bond.id:
                raise RuntimeError("unexpected packet")
            self.parse_bond(packet.command)

        self._event.set()

    async def init(self):
        is_connected = await self.client.is_connected()

        if not is_connected:
            raise RuntimeError("device connection failed")

        self.state = BandState.Connected

        logger.info(f"State: {self.state}")

        await self.client.start_notify(GATT_READ, self.receive_data)

    async def connect(self):
        await self.send_data(self.client, self.request_link_params())

        await self.wait_for_state(BandState.ReceivedLinkParams)

        await self.send_data(self.client, self.request_authentication())

        await self.wait_for_state(BandState.ReceivedAuthentication)

        await self.send_data(self.client, self.request_bond_params())

        await self.wait_for_state(BandState.ReceivedBondParams)

        await self.send_data(self.client, self.request_bond())  # TODO: not needed if status is already correct

        await self.wait_for_state(BandState.ReceivedBond)

    async def disconnect(self):
        await self.client.stop_notify(GATT_READ)
        self.state = BandState.Disconnected

    async def set_time(self):
        await self.send_data(self.client, self.request_set_time())

    def request_link_params(self) -> Packet:
        self.state = BandState.RequestedLinkParams
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

    def parse_link_params(self, command: Command):
        if TAG_ERROR in command:
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
        packet = Packet(
            service_id=DeviceConfig.id,
            command_id=DeviceConfig.Auth.id,
            command=Command(tlvs=[
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
                TLV(tag=DeviceConfig.BondParams.Tags.ClientSerial, value=self.client_serial),
                TLV(tag=DeviceConfig.BondParams.Tags.BTVersion, value=b"\x02"),
                TLV(tag=DeviceConfig.BondParams.Tags.MaxFrameSize),
                TLV(tag=DeviceConfig.BondParams.Tags.ClientMacAddress, value=self.client_mac.encode()),
                TLV(tag=DeviceConfig.BondParams.Tags.EncryptionCounter),
            ])
        )

        self.state = BandState.RequestedBondParams

        return packet

    def parse_bond_params(self, command: Command):
        if TAG_ERROR in command:
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
        iv = self._next_iv()

        packet = Packet(
            service_id=DeviceConfig.id,
            command_id=DeviceConfig.Bond.id,
            command=Command(tlvs=[
                TLV(tag=1),
                TLV(tag=3, value=b"\x00"),
                TLV(tag=5, value=self.client_serial),
                TLV(tag=6, value=create_bonding_key(self.device_mac, self.secret, iv)),
                TLV(tag=7, value=iv),
            ])
        )

        self.state = BandState.RequestedBond

        return packet

    def parse_bond(self, command):
        if TAG_ERROR in command:
            raise RuntimeError("bond negotiation failed")

        self.state = BandState.ReceivedBond

    def request_set_time(self):
        zone_hours, zone_minutes = divmod(time.timezone / -3600, 1)
        zone_minutes *= 60

        offset = encode_int(int(zone_hours), length=1) + encode_int(int(zone_minutes), length=1)

        packet = Packet(
            service_id=DeviceConfig.id,
            command_id=DeviceConfig.SetTime.id,
            command=Command(tlvs=[
                TLV(tag=DeviceConfig.SetTime.Tags.Timestamp, value=encode_int(int(time.time()), length=4)),
                TLV(tag=DeviceConfig.SetTime.Tags.ZoneOffset, value=offset),
            ]).encrypt(self.secret, self._next_iv()),
        )

        return packet


async def run(config, loop):
    secret = base64.b64decode(config["secret"])
    device_uuid = config["device_uuid"]
    device_mac = config["device_mac"]
    client_mac = config["client_mac"]

    async with BleakClient(device_mac if platform.system() != "Darwin" else device_uuid, loop=loop) as client:
        band = Band(client=client, client_mac=client_mac, device_mac=device_mac, secret=secret, loop=loop)
        await band.init()
        await band.connect()
        await band.set_time()
        await band.disconnect()


def main():
    config = ConfigParser()

    if not CONFIG_FILE.exists():
        config[DEVICE_NAME] = {
            "device_uuid": "A0E49DB2-XXXX-XXXX-XXXX-D75121192329",
            "device_mac": "6C:B7:49:XX:XX:XX",
            "client_mac": "C4:B3:01:XX:XX:XX",
            "secret": base64.b64encode(generate_nonce()).decode(),
        }

        with open(CONFIG_FILE.name, "w") as fp:
            config.write(fp)

        return

    config.read(CONFIG_FILE.name)

    event_loop = asyncio.get_event_loop()
    event_loop.run_until_complete(run(config[DEVICE_NAME], event_loop))


if __name__ == "__main__":
    main()
