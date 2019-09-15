import asyncio
import logging
import platform
import struct
from configparser import ConfigParser

from bleak import BleakClient

DEVICE_NAME = "default"

logging.basicConfig(level=logging.DEBUG)

CHARACTERISTICS = {
    "Battery Level": "00002a19-0000-1000-8000-00805f9b34fb",
    "Model Number": "00002a24-0000-1000-8000-00805f9b34fb",
    "Firmware Revision": "00002a26-0000-1000-8000-00805f9b34fb",
    "Software Revision": "00002a28-0000-1000-8000-00805f9b34fb",
    "Manufacturer Name": "00002a29-0000-1000-8000-00805f9b34fb",
    # "Heart Rate Measurement": "00002a37-0000-1000-8000-00805f9b34fb",  # Not permitted
    "Body Sensor Location": "00002a38-0000-1000-8000-00805f9b34fb",
}

BODY_SENSOR_LOCATIONS = {
    0: "Other",
    1: "Chest",
    2: "Wrist",
    3: "Finger",
    4: "Hand",
    5: "Ear Lobe",
    6: "Foot",
}


async def read_data(loop):
    config = ConfigParser()
    config.read("band.ini")

    device_uuid = config[DEVICE_NAME]["device_uuid"]
    device_mac = config[DEVICE_NAME]["device_mac"]

    async with BleakClient(device_mac if platform.system() != "Darwin" else device_uuid, loop=loop) as client:
        for name, uuid in CHARACTERISTICS.items():
            characteristic = await client.read_gatt_char(uuid)

            if name == "Battery Level":
                value, *_ = struct.unpack("B", characteristic)
                print(f"Charge (0-100): {value}")
            elif name == "Body Sensor Location":
                value, *_ = struct.unpack("B", characteristic)
                print(f"Location: {BODY_SENSOR_LOCATIONS[value]}")
            else:
                print(f"{name}: {characteristic}")


event_loop = asyncio.get_event_loop()

try:
    event_loop.run_until_complete(read_data(event_loop))
finally:
    event_loop.close()
