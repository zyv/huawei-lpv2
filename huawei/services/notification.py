from enum import IntEnum, unique
from typing import TypeVar

from ..protocol import TLV, Command, Packet, encode_int, encrypt_packet


class Notification:
    id = 2

    class Message:
        id = 1

        @unique
        class Tags(IntEnum):
            Id = 1
            Type = 2
            Vibrate = 3

            PayloadEmpty = 4

            ImageHeight = 8
            ImageWidth = 9
            ImageColor = 10
            ImageData = 11

            TextKind = 14
            TextEncoding = 15
            TextContent = 16

            PayloadText = 132
            PayloadImage = 134

            TextList = 140
            TextItem = 141


@unique
class NotificationType(IntEnum):
    Call = 1
    SMS = 2
    WeChat = 3
    QQ = 11
    MissedCall = 14
    Email = 15
    Generic = 127


@unique
class TextKind(IntEnum):
    Text = 1
    Sender = 2
    Title = 3

    YellowPage = 5
    ContentSign = 6

    Flight = 7
    Train = 8
    WarmRemind = 9
    Weather = 10


TITLE_TEXT_KIND = {
    NotificationType.Call: TextKind.Sender,
    NotificationType.SMS: TextKind.Sender,
    NotificationType.WeChat: TextKind.Sender,
    NotificationType.QQ: TextKind.Sender,
    NotificationType.MissedCall: TextKind.Title,
    NotificationType.Email: TextKind.Title,
    NotificationType.Generic: TextKind.Title,
}

TEXT_ENCODING = 2  # yet unclear what scheme identified as "1" is for

T = TypeVar("T")


def optional_list(item: T, condition: bool) -> list[T]:
    return [item] if condition else []


def text_item(kind: TextKind, content: str) -> TLV:
    tags = Notification.Message.Tags

    return TLV(
        tag=tags.TextItem,
        value=bytes(
            Command(
                tlvs=[
                    TLV(tag=tags.TextKind, value=encode_int(kind.value, length=1)),
                    TLV(tag=tags.TextEncoding, value=encode_int(TEXT_ENCODING, length=1)),
                    TLV(tag=tags.TextContent, value=content.encode()),
                ],
            ),
        ),
    )


def text_payload(notification_type: NotificationType, text: str, title: str) -> TLV:
    return TLV(
        tag=Notification.Message.Tags.TextList,
        value=bytes(
            Command(
                tlvs=(
                    optional_list(text_item(TITLE_TEXT_KIND[notification_type], title), title is not None)
                    + [text_item(TextKind.Text, text)]
                ),
            ),
        ),
    )


@encrypt_packet
def send_notification(
    message_id: int,
    text: str,
    title: str,
    vibrate: bool,
    notification_type: NotificationType,
) -> Packet:

    tags = Notification.Message.Tags

    return Packet(
        service_id=Notification.id,
        command_id=Notification.Message.id,
        command=Command(
            tlvs=[
                TLV(tag=tags.Id, value=encode_int(message_id)),
                TLV(tag=tags.Type, value=encode_int(notification_type.value, length=1)),
                TLV(tag=tags.Vibrate, value=encode_int(int(vibrate), length=1)),
                TLV(tag=tags.PayloadText, value=bytes(Command(tlvs=[text_payload(notification_type, text, title)]))),
            ],
        ),
    )
