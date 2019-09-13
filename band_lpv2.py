import asyncio
import base64
import enum
import logging
import platform
import time
from configparser import ConfigParser
from datetime import datetime
from pathlib import Path

from bleak import BleakClient

import huawei.commands
from huawei.protocol import AUTH_VERSION, Command, ENCRYPTION_COUNTER_MAX, NONCE_LENGTH, PROTOCOL_VERSION, Packet, \
    decode_int, digest_response, encode_int, generate_nonce, hexlify
from huawei.services import DeviceConfig, MeasurementSystem, TAG_RESULT

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

        self.client_serial = client_mac.replace(":", "")[-6:]  # android.os.Build.SERIAL

        self.max_frame_size = 254
        self.max_link_size = 254
        self.connection_interval = 10  # milliseconds

        self.server_nonce = None
        self.client_nonce = generate_nonce()

        self.bond_status = None
        self.bond_status_info = None
        self.bt_version = None
        self.encryption_counter = 0

        self._event = asyncio.Event()

    def _next_iv(self):
        if self.encryption_counter == ENCRYPTION_COUNTER_MAX:
            self.encryption_counter = 1
        self.encryption_counter += 1
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
            self._parse_link_params(packet.command)
        elif self.state == BandState.RequestedAuthentication:
            if packet.service_id != DeviceConfig.id and packet.command_id != DeviceConfig.Auth.id:
                raise RuntimeError("unexpected packet")
            self._parse_authentication(packet.command)
        elif self.state == BandState.RequestedBondParams:
            if packet.service_id != DeviceConfig.id and packet.command_id != DeviceConfig.BondParams.id:
                raise RuntimeError("unexpected packet")
            self._parse_bond_params(packet.command)
        elif self.state == BandState.RequestedBond:
            if packet.service_id != DeviceConfig.id and packet.command_id != DeviceConfig.Bond.id:
                raise RuntimeError("unexpected packet")
            self._parse_bond(packet.command)

        self._event.set()

    async def init(self):
        is_connected = await self.client.is_connected()

        if not is_connected:
            raise RuntimeError("device connection failed")

        self.state = BandState.Connected

        logger.info(f"State: {self.state}")

        await self.client.start_notify(GATT_READ, self.receive_data)

    async def connect(self):
        await self.send_data(self.client, self._request_link_params())

        await self.wait_for_state(BandState.ReceivedLinkParams)

        await self.send_data(self.client, self._request_authentication())

        await self.wait_for_state(BandState.ReceivedAuthentication)

        await self.send_data(self.client, self._request_bond_params())

        await self.wait_for_state(BandState.ReceivedBondParams)

        await self.send_data(self.client, self._request_bond())  # TODO: not needed if status is already correct

        await self.wait_for_state(BandState.ReceivedBond)

    async def disconnect(self):
        await asyncio.sleep(0.5)

        await self.client.stop_notify(GATT_READ)

        self.state = BandState.Disconnected

    async def set_time(self):
        await self.send_data(self.client, self._request_set_time())

    async def set_locale(self, language_tag: str = "en-US", measurement_system: int = MeasurementSystem.Metric):
        packet = huawei.commands.set_locale(language_tag, measurement_system, self.secret, self._next_iv())
        await self.send_data(self.client, packet)

    def _request_link_params(self) -> Packet:
        self.state = BandState.RequestedLinkParams
        return huawei.commands.request_link_params()

    def _parse_link_params(self, command: Command):
        if TAG_RESULT in command:
            raise RuntimeError("link parameter negotiation failed")

        protocol_version = decode_int(command[DeviceConfig.LinkParams.Tags.ProtocolVersion].value)
        self.max_frame_size = decode_int(command[DeviceConfig.LinkParams.Tags.MaxFrameSize].value)
        self.max_link_size = decode_int(command[DeviceConfig.LinkParams.Tags.MaxLinkSize].value)
        self.connection_interval = decode_int(command[DeviceConfig.LinkParams.Tags.ConnectionInterval].value)

        auth_version = decode_int(command[DeviceConfig.LinkParams.Tags.ServerNonce].value[:2])
        self.server_nonce = bytes(command[DeviceConfig.LinkParams.Tags.ServerNonce].value[2:18])

        # TODO: optional path extend number parsing

        if protocol_version != PROTOCOL_VERSION:
            raise RuntimeError(f"protocol version mismatch: {protocol_version} != {PROTOCOL_VERSION}")

        if auth_version != AUTH_VERSION:
            raise RuntimeError(f"authentication scheme version mismatch: {auth_version} != {AUTH_VERSION}")

        if len(self.server_nonce) != NONCE_LENGTH:
            raise RuntimeError(f"server nonce length mismatch: {len(self.server_nonce)} != {NONCE_LENGTH}")

        logger.info(
            f"Negotiated link parameters: "
            f"{self.max_frame_size}, "
            f"{self.max_link_size}, "
            f"{self.connection_interval}, "
            f"{hexlify(self.server_nonce)}",
        )

        self.state = BandState.ReceivedLinkParams

    def _request_authentication(self):
        self.state = BandState.RequestedAuthentication
        return huawei.commands.request_authentication(client_nonce=self.client_nonce, server_nonce=self.server_nonce)

    def _parse_authentication(self, command: Command):
        expected_answer = digest_response(self.client_nonce, self.server_nonce)
        provided_answer = command[DeviceConfig.Auth.Tags.Challenge].value

        if expected_answer != provided_answer:
            raise RuntimeError(f"wrong answer to provided challenge: {expected_answer} != {provided_answer}")

        self.state = BandState.ReceivedAuthentication

    def _request_bond_params(self):
        self.state = BandState.RequestedBondParams
        return huawei.commands.request_bond_params(self.client_serial, self.client_mac)

    def _parse_bond_params(self, command: Command):
        if TAG_RESULT in command:
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
            f"{self.encryption_counter}",
        )

        self.state = BandState.ReceivedBondParams

    def _request_bond(self):
        self.state = BandState.RequestedBond
        return huawei.commands.request_bond(self.client_serial, self.device_mac, self.secret, self._next_iv())

    def _parse_bond(self, command):
        if TAG_RESULT in command:
            raise RuntimeError("bond negotiation failed")

        self.state = BandState.ReceivedBond

    def _request_set_time(self):
        ts = time.time()

        utc_offset = (datetime.fromtimestamp(ts) - datetime.utcfromtimestamp(ts)).total_seconds() / 3600
        float_hours, float_minutes = divmod(utc_offset, 1)

        offset_hours = int(abs(float_hours) + 128) if float_hours < 0 else int(float_hours)
        offset_minutes = int(abs(float_minutes * 60))

        return huawei.commands.request_set_time(ts, offset_hours, offset_minutes, self.secret, self._next_iv())


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
        await band.set_locale()
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
