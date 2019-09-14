from ..protocol import Command, Packet, TLV, encode_int, encrypt_packet


class LocaleConfig:
    id = 12

    class SetLocale:
        id = 1

        class Tags:
            LanguageTag = 1  # IETF BCP 47 language tag, see https://tools.ietf.org/html/rfc5646
            MeasurementSystem = 2


class MeasurementSystem:
    Metric = 0
    Imperial = 1


@encrypt_packet
def set_locale(language_tag: str, measurement_system: int) -> Packet:
    return Packet(
        service_id=LocaleConfig.id,
        command_id=LocaleConfig.SetLocale.id,
        command=Command(tlvs=[
            TLV(tag=LocaleConfig.SetLocale.Tags.LanguageTag, value=language_tag.encode()),
            TLV(tag=LocaleConfig.SetLocale.Tags.MeasurementSystem, value=encode_int(measurement_system, length=1)),
        ]),
    )
