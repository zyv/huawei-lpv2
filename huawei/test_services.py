import unittest
from datetime import datetime, timedelta

from .protocol import Command, Packet, TLV
from .services import fitness
from .services.fitness import ActivityTotals, HeartRate, MotionType, TodayTotals


class TestFitness(unittest.TestCase):
    def test_process_total_totals(self):
        packet = Packet(service_id=7, command_id=3, command=Command(tlvs=[TLV(tag=129, value=bytes(Command(tlvs=[
            TLV(tag=2, value=bytes.fromhex("00 00 00 0C")),
            TLV(tag=131, value=bytes(Command(tlvs=[
                TLV(tag=4, value=bytes.fromhex("01")),
                TLV(tag=5, value=bytes.fromhex("00 00 02 70")),
                TLV(tag=6, value=bytes.fromhex("00 0C")),
                TLV(tag=7, value=bytes.fromhex("00 00 01 8C"))]))),
            TLV(tag=131, value=bytes(Command(tlvs=[
                TLV(tag=4, value=bytes.fromhex("02")),
                TLV(tag=5, value=bytes.fromhex("00 00 00 00")),
                TLV(tag=6, value=bytes.fromhex("00 00")),
                TLV(tag=7, value=bytes.fromhex("00 00 00 00"))]))),
            TLV(tag=131, value=bytes(Command(tlvs=[
                TLV(tag=4, value=bytes.fromhex("03")),
                TLV(tag=5, value=bytes.fromhex("00 00 00 00")),
                TLV(tag=6, value=bytes.fromhex("00 00")),
                TLV(tag=7, value=bytes.fromhex("00 00 00 00"))]))),
            TLV(tag=131, value=bytes(Command(tlvs=[
                TLV(tag=4, value=bytes.fromhex("04")),
                TLV(tag=6, value=bytes.fromhex("00 4F")),
                TLV(tag=7, value=bytes.fromhex("00 00 00 7B"))]))),
            TLV(tag=131, value=bytes(Command(tlvs=[
                TLV(tag=4, value=bytes.fromhex("06")),
                TLV(tag=6, value=bytes.fromhex("00 00")),
                TLV(tag=8, value=bytes.fromhex("01 E6"))]))),
            TLV(tag=131, value=bytes(Command(tlvs=[
                TLV(tag=4, value=bytes.fromhex("07")),
                TLV(tag=6, value=bytes.fromhex("00 00")),
                TLV(tag=8, value=bytes.fromhex("01 E6"))]))),
            TLV(tag=9, value=bytes.fromhex("5D 7C 9C FA 32"))])))]))

        self.assertEqual(
            TodayTotals(
                calories=12,
                # Reference datetime should be in the local timezone!
                heart_rate=HeartRate(time=datetime.fromtimestamp(1568447738.0), rate=50),
                activities=[
                    ActivityTotals(type=MotionType.Walking, calories=12, steps=624, distance=396),
                    ActivityTotals(type=MotionType.Running, calories=0, steps=0, distance=0),
                    ActivityTotals(type=MotionType.Climbing, calories=0, steps=0, distance=0),
                    ActivityTotals(type=MotionType.Cycling, calories=79, distance=123),
                    ActivityTotals(type=MotionType.ShallowSleep, calories=0, time=timedelta(seconds=29160)),
                    ActivityTotals(type=MotionType.DeepSleep, calories=0, time=timedelta(seconds=29160)),
                ],
            ),
            fitness.process_today_totals(packet.command),
        )
