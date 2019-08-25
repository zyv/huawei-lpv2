import asyncio
import logging
import struct
import platform

from bleak import BleakClient

logging.basicConfig(level=logging.DEBUG)

DEVICE_ADDRESS = "A0E49DB2-XXXX-XXXX-XXXX-D75121192329"
DEVICE_MAC = "6C:B7:49:XX:XX:XX"

CHARACTERISTICS = {
    "Battery Level": "00002a19-0000-1000-8000-00805f9b34fb",
    "Model Number": "00002a24-0000-1000-8000-00805f9b34fb",
    "Firmware Revision": "00002a26-0000-1000-8000-00805f9b34fb",
    "Software Revision": "00002a28-0000-1000-8000-00805f9b34fb",
    "Manufacturer Name": "00002a29-0000-1000-8000-00805f9b34fb",
    # "Heart Rate Measurement": "00002a37-0000-1000-8000-00805f9b34fb",  # Not permitted
    "Body Sensor Location": "00002a38-0000-1000-8000-00805f9b34fb",
    # "GATT_WRITE": "0000fe01-0000-1000-8000-00805f9b34fb",
    # "GATT_READ": "0000fe02-0000-1000-8000-00805f9b34fb",
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


async def read_data(address, loop):
    async with BleakClient(address, loop=loop) as client:
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


loop = asyncio.get_event_loop()
loop.run_until_complete(read_data(DEVICE_MAC if platform.system() != "Darwin" else DEVICE_ADDRESS, loop))
