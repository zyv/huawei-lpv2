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
            PathExtendNumber = 6  # apparently used for BTVersion == 0

            Error = 127

    class SetTime:
        id = 5

        class Tags:
            Timestamp = 1
            ZoneOffset = 2

    class ProductType:
        id = 7

        class Tags:
            ProductType = 2  # for request
            HardwareVersion = 3
            SoftwareVersion = 7
            SerialNumber = 9
            ProductModel = 12

    class Bond:
        id = 14

        class Tags:
            Status = 2

            Error = 127

    class BondParams:
        id = 15

        class Tags:
            Status = 1
            StatusInfo = 2
            ClientSerial = 3
            BTVersion = 4
            MaxFrameSize = 5
            ClientMacAddress = 7
            EncryptionCounter = 9

            Error = 127

    class Auth:
        id = 19

        class Tags:
            Challenge = 1
            Nonce = 2
