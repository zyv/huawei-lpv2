import asyncio
import base64
import enum
import logging
import platform
from configparser import ConfigParser
from datetime import datetime
from pathlib import Path

from bleak import BleakClient

from huawei.protocol import Command, ENCRYPTION_COUNTER_MAX, Packet, encode_int, generate_nonce, hexlify
from huawei.services import TAG_RESULT
from huawei.services import device_config
from huawei.services import locale_config
from huawei.services.device_config import DeviceConfig

DEVICE_NAME = "default"

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

CONFIG_FILE = Path("band.ini")

GATT_WRITE = "0000fe01-0000-1000-8000-00805f9b34fb"
GATT_READ = "0000fe02-0000-1000-8000-00805f9b34fb"


class BandState(enum.Enum):
    Connected = enum.auto()

    RequestedLinkParams = enum.auto()
    ReceivedLinkParams = enum.auto()
    RequestedAuthentication = enum.auto()
    ReceivedAuthentication = enum.auto()
    RequestedBondParams = enum.auto()
    ReceivedBondParams = enum.auto()
    RequestedBond = enum.auto()
    ReceivedBond = enum.auto()

    Ready = enum.auto()

    RequestedAck = enum.auto()
    ReceivedAck = enum.auto()

    Disconnected = enum.auto()


class Band:
    def __init__(self, client: BleakClient, client_mac: str, device_mac: str, secret: bytes, loop):
        self.state = BandState.Disconnected

        self.client = client
        self.client_mac = client_mac
        self.device_mac = device_mac
        self.secret = secret
        self.loop = loop

        self.client_serial = client_mac.replace(":", "")[-6:]  # android.os.Build.SERIAL

        self.link_params = None

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

    async def _wait_for_state(self, state: BandState, reset_state: bool = True):
        logger.debug(f"Waiting for state: {state}...")

        await self._event.wait()

        if self.state != state:
            raise RuntimeError(f"bad state: {self.state} != {state}")

        logger.debug(f"Response received, state {state} attained!")

        if reset_state:
            self.state = BandState.Ready
            logger.debug(f"State reset: {self.state}")

        self._event.clear()

    def _send_data(self, packet: Packet, new_state: BandState = BandState.RequestedAck):
        data = bytes(packet)
        logger.debug(f"State: {self.state}, sending: {hexlify(data)}")

        self.state = new_state
        logger.debug(f"Switched to state: {new_state}")

        return self.client.write_gatt_char(GATT_WRITE, data)

    def _receive_data(self, sender, data):
        logger.debug(f"State: {self.state}, received from '{sender}': {hexlify(bytes(data))}")
        packet = Packet.from_bytes(data)
        logger.debug(f"Parsed packet: {packet}")

        if self.state == BandState.RequestedLinkParams:
            if (packet.service_id, packet.command_id) != (DeviceConfig.id, DeviceConfig.LinkParams.id):
                raise RuntimeError("unexpected packet")
            self._process_link_params(packet.command)
        elif self.state == BandState.RequestedAuthentication:
            if (packet.service_id, packet.command_id) != (DeviceConfig.id, DeviceConfig.Auth.id):
                raise RuntimeError("unexpected packet")
            self._process_authentication(packet.command)
        elif self.state == BandState.RequestedBondParams:
            if (packet.service_id, packet.command_id) != (DeviceConfig.id, DeviceConfig.BondParams.id):
                raise RuntimeError("unexpected packet")
            self._process_bond_params(packet.command)
        elif self.state == BandState.RequestedBond:
            if (packet.service_id, packet.command_id) != (DeviceConfig.id, DeviceConfig.Bond.id):
                raise RuntimeError("unexpected packet")
            self._process_bond(packet.command)
        elif self.state == BandState.RequestedAck:
            self.state = BandState.ReceivedAck

        self._event.set()

    async def connect(self):
        # TODO: decorator
        is_connected = await self.client.is_connected()

        if not is_connected:
            raise RuntimeError("device connection failed")

        await self.client.start_notify(GATT_READ, self._receive_data)

        self.state = BandState.Connected
        logger.info(f"Connected to band, state: {self.state}")

    async def handshake(self):
        await self._send_data(device_config.request_link_params(), BandState.RequestedLinkParams)
        await self._wait_for_state(BandState.ReceivedLinkParams, False)

        packet = device_config.request_authentication(self.client_nonce, self.server_nonce)
        await self._send_data(packet, BandState.RequestedAuthentication)
        await self._wait_for_state(BandState.ReceivedAuthentication, False)

        packet = device_config.request_bond_params(self.client_serial, self.client_mac)
        await self._send_data(packet, BandState.RequestedBondParams)
        await self._wait_for_state(BandState.ReceivedBondParams, False)

        packet = device_config.request_bond(self.client_serial, self.device_mac, self.secret, self._next_iv())
        await self._send_data(packet, BandState.RequestedBond)  # TODO: not needed if status is already correct
        await self._wait_for_state(BandState.ReceivedBond)

    async def disconnect(self):
        self.state = BandState.Disconnected
        await asyncio.sleep(0.5)
        await self.client.stop_notify(GATT_READ)
        logger.info(f"Stopped notifications, state: {self.state}")

    async def set_time(self):
        await self._send_data(device_config.set_time(datetime.now(), key=self.secret, iv=self._next_iv()))
        await self._wait_for_state(BandState.ReceivedAck)

    async def set_locale(self, language_tag: str, measurement_system: int):
        packet = locale_config.set_locale(language_tag, measurement_system, key=self.secret, iv=self._next_iv())
        await self._send_data(packet)
        await self._wait_for_state(BandState.ReceivedAck)

    def _process_link_params(self, command: Command):
        self.link_params, self.server_nonce = device_config.process_link_params(command)
        self.state = BandState.ReceivedLinkParams

    def _process_authentication(self, command: Command):
        device_config.process_authentication(self.client_nonce, self.server_nonce, command)
        self.state = BandState.ReceivedAuthentication

    def _process_bond_params(self, command: Command):
        self.link_params.max_frame_size, self.encryption_counter = device_config.process_bond_params(command)
        self.state = BandState.ReceivedBondParams

    def _process_bond(self, command):
        if TAG_RESULT in command:
            raise RuntimeError("bond negotiation failed")

        self.state = BandState.ReceivedBond


async def run(config, loop):
    secret = base64.b64decode(config["secret"])
    device_uuid = config["device_uuid"]
    device_mac = config["device_mac"]
    client_mac = config["client_mac"]

    async with BleakClient(device_mac if platform.system() != "Darwin" else device_uuid, loop=loop) as client:
        band = Band(client=client, client_mac=client_mac, device_mac=device_mac, secret=secret, loop=loop)
        await band.connect()
        await band.handshake()
        await band.set_time()
        await band.set_locale("en-US", locale_config.MeasurementSystem.Metric)
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
