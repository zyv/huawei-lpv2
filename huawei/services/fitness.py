from dataclasses import dataclass
from datetime import date, datetime, timedelta
from enum import IntEnum, unique
from typing import Callable, Optional

from ..protocol import TLV, Command, Packet, check_result, decode_int, encode_int, encrypt_packet, set_status


class Fitness:
    id = 7

    class SetUserInfo:
        id = 2

        @unique
        class Tags(IntEnum):
            Height = 1
            Weight = 2
            Age = 3
            BirthDate = 4
            Sex = 5
            WaistMedian = 6
            WaistMax = 7

    class GetTodayTotals:
        id = 3

        @unique
        class Tags(IntEnum):
            Request = 1
            TotalCalories = 2
            MotionType = 4
            Steps = 5
            Calories = 6
            Distance = 7
            Time = 8
            HeartRate = 9
            Height = 10
            Response = 129
            Activity = 131

    class TruSleepState:
        id = 22

        @unique
        class Tags(IntEnum):
            SetStatus = 1

    class HRMonitorState:
        id = 23

        @unique
        class Tags(IntEnum):
            SetStatus = 1


@encrypt_packet
def request_today_totals() -> Packet:
    return Packet(
        service_id=Fitness.id,
        command_id=Fitness.GetTodayTotals.id,
        command=Command(
            tlvs=[
                TLV(tag=Fitness.GetTodayTotals.Tags.Request),
            ],
        ),
    )


@unique
class MotionType(IntEnum):
    Walking = 1
    Running = 2
    Climbing = 3
    Cycling = 4
    ShallowSleep = 6
    DeepSleep = 7


@dataclass
class ActivityTotals:
    """
    N. B. Calories fields are actually in kilocalories!
    """

    type: MotionType
    calories: Optional[int] = None
    steps: Optional[int] = None
    distance: Optional[int] = None
    height: Optional[int] = None
    time: Optional[timedelta] = None


@dataclass
class HeartRate:
    """
    N.B. Sadly the device returns a timestamp in local timezone instead of UTC, so confusion is possible when crossing
         timezone boundaries.
    """

    time: datetime
    rate: int


@dataclass
class TodayTotals:
    calories: int
    heart_rate: Optional[HeartRate]
    activities: list[ActivityTotals]


@check_result
def process_today_totals(command: Command) -> TodayTotals:
    tags = Fitness.GetTodayTotals.Tags
    response = command[tags.Response].command

    def fmap(func: Callable, item: TLV, tag: int) -> Optional[int]:
        return func(item.command[tag].value) if tag in item.command else None

    return TodayTotals(
        calories=decode_int(response[tags.TotalCalories].value),
        heart_rate=(
            HeartRate(
                time=datetime.fromtimestamp(decode_int(response[tags.HeartRate].value[:-1])),
                rate=decode_int(response[tags.HeartRate].value[-1:]),
            )
            if tags.HeartRate in response
            else None
        ),
        activities=[
            ActivityTotals(
                type=MotionType(decode_int(tlv.command[tags.MotionType].value)),
                calories=fmap(decode_int, tlv, tags.Calories),
                steps=fmap(decode_int, tlv, tags.Steps),
                distance=fmap(decode_int, tlv, tags.Distance),
                height=fmap(decode_int, tlv, tags.Height),
                time=fmap(lambda item: timedelta(minutes=decode_int(item)), tlv, tags.Time),
            )
            for tlv in response.tlvs
            if tlv.tag == tags.Activity
        ],
    )


@unique
class Sex(IntEnum):
    Male = 1
    Female = 2


@encrypt_packet
def set_user_info(height: int, weight: int, sex: Sex, birth_date: date) -> Packet:
    age = int((date.today() - birth_date).days / 365.25)
    packed_birthday = (
        encode_int(birth_date.year, length=2)
        + encode_int(birth_date.month, length=1)
        + encode_int(birth_date.day, length=1)
    )
    tags = Fitness.SetUserInfo.Tags
    return Packet(
        service_id=Fitness.id,
        command_id=Fitness.SetUserInfo.id,
        command=Command(
            tlvs=[
                TLV(tag=tags.Height, value=encode_int(height, length=1)),
                TLV(tag=tags.Weight, value=encode_int(weight, length=1)),
                TLV(tag=tags.Age, value=encode_int(age, length=1)),
                TLV(tag=tags.BirthDate, value=packed_birthday),
                TLV(tag=tags.Sex, value=encode_int(sex.value, length=1)),
                TLV(tag=tags.WaistMedian, value=encode_int(int(height * 0.42), length=1)),
                TLV(tag=tags.WaistMax, value=encode_int(int(height * 0.83), length=1)),
            ],
        ),
    )


@encrypt_packet
def enable_trusleep(state: bool) -> Packet:
    return set_status(Fitness.id, Fitness.TruSleepState.id, Fitness.TruSleepState.Tags.SetStatus, state)


@encrypt_packet
def enable_heart_rate_monitoring(state: bool) -> Packet:
    return set_status(Fitness.id, Fitness.HRMonitorState.id, Fitness.HRMonitorState.Tags.SetStatus, state)
