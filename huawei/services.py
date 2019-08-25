class DeviceConfig:
    id = 1

    class LinkParams:
        id = 1

        class Tags:
            ProtocolVersion = 1
            MaxFrameSize = 2
            MaxLinkSize = 3
            ConnectionInterval = 4
            ServerNonce = 5

    class BondParams:
        id = 15

        class Tags:
            Status = 1
            StatusInfo = 2
            Serial = 3
            BTVersion = 4
            MaxFrameSize = 5
            MacAddress = 7
            EncryptionCounter = 9

    class Auth:
        id = 19

        class Tags:
            Challenge = 1
            Nonce = 2

    # SetTime = 5
    # Bond = 14
