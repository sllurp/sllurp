import unittest
from nose2.tools import params
from sllurp.messages.base import LLRPMessage, LLRPMessageHeader, \
     LLRPMessageMeta
from sllurp.messages.capabilities import GetSupportedVersion, \
     GetReaderCapabilities


class TestMessageHeader(unittest.TestCase):
    def test_build_header(self):
        mh = LLRPMessageHeader.build(dict(type=2, length=10, message_id=3))
        msg = b'\x08\x02' \
              b'\x00\x00\x00\x0a' \
              b'\x00\x00\x00\x03'
        assert mh == msg

        built = b'\x08\x41' \
                b'\x00\x00\x00\x0a' \
                b'\x00\x00\x00\x01'
        parsed = LLRPMessageHeader.parse(built)
        assert parsed.version == 2
        assert parsed.type == 65
        assert parsed.length == len(built)
        assert parsed.message_id == 1


class TestAllMessages(unittest.TestCase):
    @params(*LLRPMessageMeta.message_classes.values())
    def test_message(self, klazz):
        self.assertIsNotNone(klazz())


class TestMessage(unittest.TestCase):
    def setUp(self):
        LLRPMessage.message_id = 0


class TestBytesToClass(TestMessage):
    def test_build_from_struct(self):
        built = b'\x08\x01' \
                b'\x00\x00\x00\x0b' \
                b'\x00\x00\x00\x01\x7b'
        grc = GetReaderCapabilities._struct.parse(built)
        self.assertEqual(grc.requested_data, 0x7b)

    def test_bytes_to_class(self):
        built = b'\x08\x01' \
                b'\x00\x00\x00\x0b' \
                b'\x00\x00\x00\x01\x7b'
        msg = LLRPMessage.from_bytes(built)
        self.assertEqual(len(msg), 0x0b)
        self.assertIsInstance(msg, GetReaderCapabilities)
        self.assertEqual(msg.ty, GetReaderCapabilities.ty)
        self.assertEqual(msg.requested_data, 0x7b)

    def test_bytes_to_empty_class(self):
        built = b'\x08\x2e' \
                b'\x00\x00\x00\x0a' \
                b'\x00\x00\x00\x01'
        msg = LLRPMessage.from_bytes(built)
        self.assertIsInstance(msg, GetSupportedVersion)


class TestGetSupportedVersion(TestMessage):
    def test_build_message(self):
        gsv = GetSupportedVersion()
        self.assertEqual(gsv.length(), 10)
        built = b'\x08\x2e' \
                b'\x00\x00\x00\x0a' \
                b'\x00\x00\x00\x01'
        self.assertEqual(gsv.build(), built)
        self.assertEqual(gsv.build(), built[:-1] + b'\x02')


class TestGetReaderCapabilities(TestMessage):
    def test_build_message(self):
        grc = GetReaderCapabilities(requested_data=123)
        self.assertEqual(len(grc), 11)

        built = b'\x08\x01' \
                b'\x00\x00\x00\x0b' \
                b'\x00\x00\x00\x01\x7b'
        self.assertEqual(grc.build(), built)
        self.assertEqual(grc.requested_data, 0x7b)
