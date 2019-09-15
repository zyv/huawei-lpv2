import asyncio
import base64
import enum
import logging
import platform
from configparser import ConfigParser
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional, Tuple

from bleak import BleakClient

from huawei.protocol import Command, GATT_READ, GATT_WRITE, Packet, generate_nonce, hexlify, initialization_vector
from huawei.services import TAG_RESULT
from huawei.services import device_config
from huawei.services import locale_config

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

DEVICE_NAME = "default"
CONFIG_FILE = Path("band.ini")


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

    Disconnected = enum.auto()


class Band:
    def __init__(self, loop, client: BleakClient, client_mac: str, device_mac: str, key: bytes):
        self.state: BandState = BandState.Disconnected

        self.client: BleakClient = client
        self.loop = loop

        self.client_mac: str = client_mac
        self.device_mac: str = device_mac
        self.client_serial: str = client_mac.replace(":", "")[-6:]  # android.os.Build.SERIAL

        self._key: bytes = key
        self._server_nonce: Optional[bytes] = None
        self._client_nonce: bytes = generate_nonce()
        self._encryption_counter: int = 0

        self.link_params: Optional[device_config.LinkParams] = None

        self.bond_status: Optional[int] = None
        self.bond_status_info: Optional[int] = None
        self.bt_version: Optional[int] = None

        self._packet: Optional[Packet] = None
        self._event = asyncio.Event()

    def _credentials(self):
        self._encryption_counter, iv = initialization_vector(self._encryption_counter)
        return {"key": self._key, "iv": iv}

    async def _send_data(self, packet: Packet, new_state: BandState):
        data = bytes(packet)
        logger.debug(f"Request packet: {packet}")
        logger.debug(f"Current state: {self.state}, target state: {new_state}, sending: {hexlify(data)}")

        self.state = new_state
        await self.client.write_gatt_char(GATT_WRITE, data)

    def _receive_data(self, sender: str, data: bytes):
        logger.debug(f"Current state: {self.state}, received from '{sender}': {hexlify(bytes(data))}")
        self._packet = Packet.from_bytes(data)
        logger.debug(f"Parsed response packet: {self._packet}")

        assert self.state.name.startswith("Requested"), "unexpected packet"
        self._event.set()

    async def _process_response(self, request: Packet, func: Callable, new_state: BandState):
        logger.debug(f"Waiting for response from service_id={request.service_id}, command_id={request.command_id}...")

        await self._event.wait()
        self._event.clear()

        assert (self._packet.service_id, self._packet.command_id) == (request.service_id, request.command_id)
        func(self._packet.command)

        self.state, self._packet = new_state, None

        logger.debug(f"Response processed, attained requested state: {self.state}")

    async def _transact(self, request: Packet, func: Callable, states: Optional[Tuple[BandState, BandState]] = None):
        source_state, target_state = states if states is not None else (BandState.RequestedAck, BandState.Ready)
        await self._send_data(request, source_state)
        await self._process_response(request, func, target_state)

    async def connect(self):
        if not await self.client.is_connected():
            await self.client.connect()
        await self.client.start_notify(GATT_READ, self._receive_data)
        self.state = BandState.Connected
        logger.info(f"Connected to band, current state: {self.state}")

    async def disconnect(self):
        self.state = BandState.Disconnected
        await asyncio.sleep(0.5)
        await self.client.stop_notify(GATT_READ)
        await self.client.disconnect()
        logger.info(f"Stopped notifications, current state: {self.state}")

    async def handshake(self):
        request = device_config.request_link_params()
        states = (BandState.RequestedLinkParams, BandState.ReceivedLinkParams)
        await self._transact(request, self._process_link_params, states)

        request = device_config.request_authentication(self._client_nonce, self._server_nonce)
        states = (BandState.RequestedAuthentication, BandState.ReceivedAuthentication)
        await self._transact(request, self._process_authentication, states)

        request = device_config.request_bond_params(self.client_serial, self.client_mac)
        states = (BandState.RequestedBondParams, BandState.ReceivedBondParams)
        await self._transact(request, self._process_bond_params, states)

        # TODO: not needed if status is already correct
        request = device_config.request_bond(self.client_serial, self.device_mac, **self._credentials())
        states = (BandState.RequestedBond, BandState.ReceivedBond)
        await self._transact(request, self._process_bond, states)

        self.state = BandState.Ready
        logger.info(f"Handshake completed, current state: {self.state}")

    async def set_time(self):
        request = device_config.set_time(datetime.now(), **self._credentials())
        await self._transact(request, lambda command: None)

    async def set_locale(self, language_tag: str, measurement_system: int):
        request = locale_config.set_locale(language_tag, measurement_system, **self._credentials())
        await self._transact(request, lambda command: None)

    def _process_link_params(self, command: Command):
        assert self.state == BandState.RequestedLinkParams, "bad state"
        self.link_params, self._server_nonce = device_config.process_link_params(command)

    def _process_authentication(self, command: Command):
        assert self.state == BandState.RequestedAuthentication, "bad state"
        device_config.process_authentication(self._client_nonce, self._server_nonce, command)

    def _process_bond_params(self, command: Command):
        assert self.state == BandState.RequestedBondParams, "bad state"
        self.link_params.max_frame_size, self._encryption_counter = device_config.process_bond_params(command)

    def _process_bond(self, command):
        assert self.state == BandState.RequestedBond, "bad state"
        if TAG_RESULT in command:
            raise RuntimeError("bond negotiation failed")


async def run(config, loop):
    secret = base64.b64decode(config["secret"])
    device_uuid = config["device_uuid"]
    device_mac = config["device_mac"]
    client_mac = config["client_mac"]

    async with BleakClient(device_mac if platform.system() != "Darwin" else device_uuid, loop=loop) as client:
        band = Band(loop=loop, client=client, client_mac=client_mac, device_mac=device_mac, key=secret)
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

    try:
        event_loop.run_until_complete(run(config[DEVICE_NAME], event_loop))
    finally:
        event_loop.close()


if __name__ == "__main__":
    main()
