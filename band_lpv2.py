import asyncio
import base64
import enum
import logging
import platform
from configparser import ConfigParser
from datetime import date, datetime
from pathlib import Path
from typing import Callable, Optional, Tuple

from bleak import BleakClient

from huawei.protocol import (
    GATT_READ,
    GATT_WRITE,
    Command,
    Packet,
    check_result,
    generate_nonce,
    hexlify,
    initialization_vector,
)
from huawei.services import device_config, fitness, locale_config, notification
from huawei.services.notification import NotificationType

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

DEVICE_NAME = "default"
CONFIG_FILE = Path("band.ini")


@enum.unique
class BandState(enum.IntEnum):
    Connected = enum.auto()

    RequestedLinkParams = enum.auto()
    ReceivedLinkParams = enum.auto()
    RequestedAuthentication = enum.auto()
    ReceivedAuthentication = enum.auto()
    RequestedBondParams = enum.auto()
    ReceivedBondParams = enum.auto()
    RequestedBond = enum.auto()
    ReceivedBond = enum.auto()

    RequestedAck = enum.auto()
    Ready = enum.auto()

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
        self.__message_id: int = -1

    @property
    def _credentials(self):
        self._encryption_counter, iv = initialization_vector(self._encryption_counter)
        return {"key": self._key, "iv": iv}

    @property
    def _message_id(self) -> int:
        if self.__message_id < 256:
            self.__message_id += 1
        else:
            self.__message_id = 0
        return self.__message_id

    async def _send_data(self, packet: Packet, new_state: BandState):
        assert not self.state.name.startswith("Requested"), f"tried to send while waiting for response: {self.state}"

        data = bytes(packet)
        logger.debug(f"Request packet: {packet}")
        logger.debug(f"Current state: {self.state}, target state: {new_state}, sending: {hexlify(data)}")

        self.state = new_state
        await self.client.write_gatt_char(GATT_WRITE, bytearray(data))

    def _receive_data(self, sender: int, data: bytes):
        logger.debug(f"Current state: {self.state}, received from '{sender}': {hexlify(bytes(data))}")
        self._packet = Packet.from_bytes(data)
        logger.debug(f"Parsed response packet: {self._packet}")

        assert self.state.name.startswith("Requested"), "unexpected packet"
        self.loop.call_soon_threadsafe(self._event.set)

    async def _process_response(self, request: Packet, func: Callable, new_state: BandState):
        logger.debug(f"Waiting for response from service_id={request.service_id}, command_id={request.command_id}...")

        await self._event.wait()
        self._event.clear()

        assert (self._packet.service_id, self._packet.command_id) == (request.service_id, request.command_id)
        result = func(self._packet.command)

        self.state, self._packet = new_state, None
        logger.debug(f"Response processed, attained requested state: {self.state}")

        return result

    async def _transact(self, request: Packet, func: Callable, states: Optional[Tuple[BandState, BandState]] = None):
        source_state, target_state = states if states is not None else (BandState.RequestedAck, BandState.Ready)
        await self._send_data(request, source_state)
        return await self._process_response(request, func, target_state)

    async def connect(self):
        if not self.client.is_connected:
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

        request = device_config.request_authentication(
            self.link_params.auth_version,
            self._client_nonce,
            self._server_nonce,
        )
        states = (BandState.RequestedAuthentication, BandState.ReceivedAuthentication)
        await self._transact(request, self._process_authentication, states)

        request = device_config.request_bond_params(self.client_serial, self.client_mac)
        states = (BandState.RequestedBondParams, BandState.ReceivedBondParams)
        await self._transact(request, self._process_bond_params, states)

        # TODO: not needed if status is already correct
        request = device_config.request_bond(
            self.link_params.auth_version,
            self.client_serial,
            self.device_mac,
            **self._credentials,
        )
        states = (BandState.RequestedBond, BandState.ReceivedBond)
        await self._transact(request, self._process_bond, states)

        self.state = BandState.Ready
        logger.info(f"Handshake completed, current state: {self.state}")

    @check_result
    async def factory_reset(self):
        request = device_config.factory_reset(**self._credentials)
        return await self._transact(request, lambda _: _)

    async def get_product_info(self):
        request = device_config.request_product_info(**self._credentials)
        result = await self._transact(request, lambda _: _)
        logger.info(result)

    async def get_battery_level(self) -> int:
        request = device_config.request_battery_level(**self._credentials)
        return await self._transact(request, device_config.process_battery_level)

    @check_result
    async def set_date_format(self, date_format: device_config.DateFormat, time_format: device_config.TimeFormat):
        request = device_config.set_date_format(date_format, time_format, **self._credentials)
        return await self._transact(request, lambda _: _)

    @check_result
    async def set_time(self):
        request = device_config.set_time(datetime.now(), **self._credentials)
        return await self._transact(request, lambda _: _)

    async def set_rotation_actions(self, activate: bool = True, navigate: bool = False):
        @check_result
        async def set_status(func, state):
            request = func(state, **self._credentials)
            return await self._transact(request, lambda _: _)

        await set_status(device_config.set_activate_on_rotate, activate)
        await set_status(device_config.set_navigate_on_rotate, navigate)

    @check_result
    async def set_right_wrist(self, state: bool):
        request = device_config.set_right_wrist(state, **self._credentials)
        return await self._transact(request, lambda _: _)

    @check_result
    async def set_locale(self, language_tag: str, measurement_system: int):
        request = locale_config.set_locale(language_tag, measurement_system, **self._credentials)
        return await self._transact(request, lambda _: _)

    @check_result
    async def set_user_info(self, height: int, weight: int, sex: fitness.Sex, birth_date: date):
        request = fitness.set_user_info(height, weight, sex, birth_date, **self._credentials)
        return await self._transact(request, lambda _: _)

    async def get_today_totals(self):
        request = fitness.request_today_totals(**self._credentials)
        return await self._transact(request, fitness.process_today_totals)

    @check_result
    async def enable_trusleep(self, state: bool):
        request = fitness.enable_trusleep(state, **self._credentials)
        return await self._transact(request, lambda _: _)

    @check_result
    async def enable_heart_rate_monitoring(self, state: bool):
        request = fitness.enable_heart_rate_monitoring(state, **self._credentials)
        return await self._transact(request, lambda _: _)

    @check_result
    async def send_notification(
        self,
        text: str,
        title: Optional[str] = None,
        vibrate: bool = False,
        notification_type: NotificationType = NotificationType.Generic,
    ):
        return await self._transact(
            notification.send_notification(
                self._message_id,
                text,
                title,
                vibrate,
                notification_type,
                **self._credentials,
            ),
            lambda _: _,
        )

    def _process_link_params(self, command: Command):
        assert self.state == BandState.RequestedLinkParams, "bad state"
        self.link_params, self._server_nonce = device_config.process_link_params(command)

    def _process_authentication(self, command: Command):
        assert self.state == BandState.RequestedAuthentication, "bad state"
        device_config.process_authentication(
            self.link_params.auth_version,
            command,
            self._client_nonce,
            self._server_nonce,
        )

    def _process_bond_params(self, command: Command):
        assert self.state == BandState.RequestedBondParams, "bad state"
        self.link_params.max_frame_size, self._encryption_counter = device_config.process_bond_params(command)

    @check_result
    def _process_bond(self, command: Command):
        assert self.state == BandState.RequestedBond, "bad state"
        return command  # TLV(tag=2, value=bytes.fromhex('01'))


async def run(config, loop):
    secret = base64.b64decode(config["secret"])
    device_uuid = config["device_uuid"]
    device_mac = config["device_mac"]
    client_mac = config["client_mac"]

    async with BleakClient(device_mac if platform.system() != "Darwin" else device_uuid, loop=loop) as client:
        band = Band(loop=loop, client=client, client_mac=client_mac, device_mac=device_mac, key=secret)

        await band.connect()
        await band.handshake()

        await band.get_product_info()

        # await band.factory_reset()

        battery_level = await band.get_battery_level()
        logger.info(f"Battery level: {battery_level}")

        await band.set_right_wrist(False)
        await band.set_rotation_actions()
        await band.set_time()
        await band.set_locale("en-US", locale_config.MeasurementSystem.Metric)
        await band.set_date_format(device_config.DateFormat.YearFirst, device_config.TimeFormat.Hours24)

        await band.set_user_info(
            int(config.get("height", 170)),
            int(config.get("weight", 60)),
            fitness.Sex(int(config.get("sex", 1))),
            date.fromisoformat(config.get("birth_date", "1990-08-01")),
        )

        await band.enable_trusleep(True)
        await band.enable_heart_rate_monitoring(False)

        today_totals = await band.get_today_totals()
        logger.info(f"Today totals: {today_totals}")

        # await band.send_notification("Really nice to see you ^__^", "Hello, World!",
        #                              vibrate=True, notification_type=NotificationType.Email)

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
