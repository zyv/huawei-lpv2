import enum
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Callable, List, Optional

from ..protocol import Command, Packet, TLV, check_result, decode_int, encrypt_packet


class Fitness:
    id = 7

    class GetTodayTotals:
        id = 3

        class Tags:
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


@encrypt_packet
def request_today_totals() -> Packet:
    return Packet(
        service_id=Fitness.id,
        command_id=Fitness.GetTodayTotals.id,
        command=Command(tlvs=[
            TLV(tag=Fitness.GetTodayTotals.Tags.Request),
        ]),
    )


class MotionType(enum.Enum):
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
    calories: int
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
    heart_rate: HeartRate
    activities: List[ActivityTotals]


@check_result
def process_today_totals(command: Command) -> TodayTotals:
    tags = Fitness.GetTodayTotals.Tags
    response = command[tags.Response].command

    def fmap(func: Callable, item: TLV, tag: int) -> Optional[int]:
        return func(item.command[tag].value) if tag in item.command else None

    return TodayTotals(
        calories=(decode_int(response[tags.TotalCalories].value)),
        heart_rate=HeartRate(
            time=datetime.fromtimestamp(decode_int(response[tags.HeartRate].value[:-1])),
            rate=decode_int(response[tags.HeartRate].value[-1:]),
        ),
        activities=[
            ActivityTotals(
                type=MotionType(decode_int(tlv.command[tags.MotionType].value)),
                calories=decode_int(tlv.command[tags.Calories].value),
                steps=fmap(decode_int, tlv, tags.Steps),
                distance=fmap(decode_int, tlv, tags.Distance),
                height=fmap(decode_int, tlv, tags.Height),
                time=fmap(lambda item: timedelta(minutes=decode_int(item)), tlv, tags.Time),
            )
            for tlv in response.tlvs if tlv.tag == tags.Activity
        ],
    )
