import asyncio
import unittest

from .protocol import AES_KEY_SIZE, Command, ENCRYPTION_COUNTER_MAX, HUAWEI_LPV2_MAGIC, NONCE_LENGTH, Packet, TLV, \
    VarInt, check_result, compute_digest, create_bonding_key, create_secret_key, decode_int, decrypt, encode_int, \
    encrypt, encrypt_packet, generate_nonce, hexlify, initialization_vector, process_result, set_status
from .services import CryptoTags, RESULT_ERROR, RESULT_SUCCESS, TAG_RESULT


class TestUtils(unittest.TestCase):
    COMMAND_SUCCESS = Command(tlvs=[TLV(tag=TAG_RESULT, value=encode_int(RESULT_SUCCESS, length=4))])
    COMMAND_ERROR = Command(tlvs=[TLV(tag=TAG_RESULT, value=encode_int(RESULT_ERROR, length=4))])
    COMMAND_NEUTRAL = Command(tlvs=[TLV(tag=1, value=b"abc")])

    def test_hexlify(self):
        self.assertEqual("", hexlify(b""))
        self.assertEqual("31 32 33 34 35", hexlify(b"12345"))

    def test_int_encoding(self):
        self.assertEqual(list(range(1000)), [decode_int(encode_int(i)) for i in range(1000)])

    def test_initialization_vector(self):
        counter, iv = initialization_vector(7)
        self.assertEqual((8,) * 2, (counter, decode_int(iv[-4:])))

        counter, iv = initialization_vector(ENCRYPTION_COUNTER_MAX)
        self.assertEqual((1,) * 2, (counter, decode_int(iv[-4:])))

    def test_encrypt_packet(self):
        self.assertRaises(TypeError, encrypt_packet(lambda: TestPacket.PACKET))

        key, iv = generate_nonce(), generate_nonce()
        packet = encrypt_packet(lambda: TestPacket.PACKET)(key=key, iv=iv)
        self.assertEqual(TestPacket.PACKET, packet.decrypt(key, iv))

    def test_process_result(self):
        self.assertEqual(RESULT_SUCCESS, process_result(self.COMMAND_SUCCESS))
        self.assertEqual(RESULT_ERROR, process_result(self.COMMAND_ERROR))
        self.assertIsNone(process_result(self.COMMAND_NEUTRAL))

    def test_check_result(self):
        # function
        self.assertTrue(check_result(lambda _: True)(self.COMMAND_SUCCESS))
        self.assertTrue(check_result(lambda _: True)(self.COMMAND_NEUTRAL))
        self.assertRaises(ValueError, check_result(lambda _: True), self.COMMAND_ERROR)

        # bound method
        self.assertRaises(ValueError, check_result(lambda _, __: True), object(), self.COMMAND_ERROR)

        # coroutine
        @check_result
        async def coroutine():
            return self.COMMAND_ERROR

        def testbed():
            return asyncio.get_event_loop().run_until_complete(coroutine())

        self.assertRaises(ValueError, testbed)

    def test_set_status(self):
        self.assertEqual(
            set_status(1, 2, 3, False),
            Packet(service_id=1, command_id=2, command=Command(tlvs=[
                TLV(tag=3, value=b"\x00"),
            ])),
        )


class TestVarInt(unittest.TestCase):
    INTS = [0, 1, 127, 128, 8193, 16383, 16384]
    BYTES = [b"\x00", b"\x01", b"\x7F", b"\x81\x00", b"\xC0\x01", b"\xFF\x7F", b"\x81\x80\x00"]

    def test_serialization(self):
        self.assertEqual(self.BYTES, [bytes(VarInt(i)) for i in self.INTS])

    def test_deserialization(self):
        self.assertEqual(self.INTS, [int(VarInt.from_bytes(i)) for i in self.BYTES])

    def test_roundtrip(self):
        numbers = list(range(1000))
        self.assertEqual(numbers, [int(VarInt.from_bytes(bytes(VarInt(i)))) for i in numbers])

    def test_equality(self):
        self.assertEqual(VarInt(1), VarInt(1))
        self.assertNotEqual(VarInt(1), VarInt(2))

    def test_length(self):
        self.assertEqual([len(x) for x in self.BYTES], [len(VarInt(i)) for i in self.INTS])


class TestTLV(unittest.TestCase):
    TEST_TLV = TLV(tag=1, value=b"abc")
    TEST_BYTES = b"\x01\x03abc"

    def test_serialization(self):
        self.assertEqual(self.TEST_BYTES, bytes(self.TEST_TLV))

    def test_deserialization(self):
        self.assertEqual(self.TEST_TLV, TLV.from_bytes(self.TEST_BYTES))

    def test_nested_tlvs(self):
        nested_tlvs = TLV(tag=132, value=bytes(Command(tlvs=[
            TLV(tag=140, value=bytes(Command(tlvs=[
                TLV(tag=141, value=bytes(Command(tlvs=[self.TEST_TLV]))),
            ]))),
        ])))

        self.assertEqual(132, TLV.from_bytes(bytes(nested_tlvs)).tag)
        self.assertEqual(None, TLV.from_bytes(bytes(nested_tlvs)).command[140].command[141].command[1].command)
        self.assertEqual([self.TEST_TLV], TLV.from_bytes(bytes(nested_tlvs)).command[140].command[141].command.tlvs)

    def test_equality(self):
        tlv1, tlv2, tlv3 = self.TEST_TLV, TLV(tag=1, value=b"abc"), TLV(tag=1, value=b"cde")
        self.assertEqual(tlv1, tlv2)
        self.assertNotEqual(tlv1, tlv3)


class TestCommand(unittest.TestCase):
    DATA = "01 00 02 00 03 00 04 00"

    def test_serialization(self):
        cmd1, cmd2 = Command(), Command(tlvs=[TLV(tag=1, value=b"abc"), TLV(tag=2, value=b"cde")])
        self.assertEqual(b"", bytes(cmd1))
        self.assertEqual(b"\x01\x03abc\x02\x03cde", bytes(cmd2))

        self.assertEqual(cmd2[2], TLV(tag=2, value=b"cde"))

    def test_deserialization(self):
        cmd = Command.from_bytes(bytes.fromhex(self.DATA))

        self.assertEqual(4, len(cmd.tlvs))
        self.assertEqual([1, 2, 3, 4], [tlv.tag for tlv in cmd.tlvs])
        self.assertEqual([b""] * 4, [tlv.value for tlv in cmd.tlvs])

        self.assertEqual(cmd[3], TLV(tag=3, value=b""))

    def test_contains(self):
        cmd = Command.from_bytes(bytes.fromhex(self.DATA))
        self.assertTrue(all(tag in cmd for tag in [1, 2, 3, 4]))
        self.assertFalse(5 in cmd)

    def test_crypto(self):
        command_plain = Command(tlvs=[TLV(tag=1, value=b"abc"), TLV(tag=2, value=b"cde")])

        key, iv = generate_nonce(), generate_nonce()
        command_encrypted = command_plain.encrypt(key, iv)

        self.assertTrue(all(
            tag in command_encrypted for tag in
            (CryptoTags.Encryption, CryptoTags.InitVector, CryptoTags.Encryption)
        ))

        self.assertEqual(b"\x01", command_encrypted[CryptoTags.Encryption].value)
        self.assertEqual(iv, command_encrypted[CryptoTags.InitVector].value)

        self.assertTrue(command_plain == command_encrypted.decrypt(key, iv))


class TestPacket(unittest.TestCase):
    DATA = "5A 00 08 00 01 02 03 03 61 62 63 E1 D3"
    PACKET = Packet(service_id=1, command_id=2, command=Command(tlvs=[TLV(tag=3, value=b"abc")]))

    def test_deserialization(self):
        self.assertRaisesRegex(ValueError, r"packet too short", Packet.from_bytes, b"")
        self.assertRaisesRegex(ValueError, r"magic mismatch", Packet.from_bytes, b"123456")
        self.assertRaisesRegex(ValueError, r"checksum mismatch", Packet.from_bytes, HUAWEI_LPV2_MAGIC + b"123456")

        self.assertEqual(self.PACKET, Packet.from_bytes(bytes.fromhex(self.DATA)))

    def test_serialization(self):
        self.assertEqual(bytes.fromhex(self.DATA), bytes(self.PACKET))

    def test_crypto(self):
        key, iv = generate_nonce(), generate_nonce()
        encrypted_command = self.PACKET.command.encrypt(key, iv)
        encrypted_packet = self.PACKET.encrypt(key, iv)
        self.assertEqual(encrypted_command, encrypted_packet.command)
        self.assertEqual(self.PACKET, encrypted_packet.decrypt(key, iv))


class TestCrypto(unittest.TestCase):
    MAC_ADDRESS = "FF:FF:FF:FF:FF:CC"
    SECRET_KEY = bytes.fromhex("EE FF 25 87 2A BB 19 1A 15 37 85 24 AF C0 89 E6")
    DIGEST = "BD 37 66 40 CD 62 73 FB AE A3 25 1B F3 4F 51 3D E3 B5 F3 4A 95 DC 9B 6F FD DB 93 AD 59 67 03 B0"

    def test_generate_nonce(self):
        self.assertEqual(AES_KEY_SIZE, NONCE_LENGTH)
        self.assertEqual(AES_KEY_SIZE, len(generate_nonce()))

    def test_digest(self):
        self.assertEqual(bytes.fromhex(self.DIGEST), compute_digest("", b"", b""))

    def test_secret_key(self):
        self.assertEqual(self.SECRET_KEY, create_secret_key(self.MAC_ADDRESS))

    def test_roundtrip(self):
        data, key, iv = generate_nonce() + b"abc", generate_nonce(), generate_nonce()
        self.assertEqual(data, decrypt(encrypt(data, key, iv), key, iv))

    def test_bonding_key(self):
        key, iv = generate_nonce(), generate_nonce()
        bonding_key = create_bonding_key(self.MAC_ADDRESS, key, iv)
        self.assertEqual(key, decrypt(bonding_key, self.SECRET_KEY, iv))
