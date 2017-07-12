import unittest
import random
import sllurp
import sllurp.llrp
import sllurp.llrp_proto
import sllurp.llrp_errors
import binascii
import logging


logLevel = logging.WARNING
logging.basicConfig(level=logLevel,
                    format='%(asctime)s %(name)s: %(levelname)s: %(message)s')
logger = logging.getLogger('sllurp')
logger.setLevel(logLevel)


def randhex(numdigits):
    """Return a string with numdigits hexadecimal digits."""
    assert type(numdigits) is int
    return '{{:0{}x}}'.format(numdigits).format(
        random.randrange(16**numdigits))


def hex_to_bytes(hexdata):
    binrep = binascii.unhexlify(hexdata)
    assert len(binrep) == (len(hexdata) / 2)
    return binrep


def bytes_to_hex(bindata):
    ascrep = binascii.hexlify(bindata)
    assert len(ascrep) == (len(bindata) * 2)
    return ascrep


class MockStream(object):
    _bytes = None

    def __init__(self, mybytes):
        self._bytes = mybytes

    def recv(self, length):
        if length > len(self._bytes):
            length = len(self._bytes)
        data = self._bytes[:length]
        self._bytes = self._bytes[length:]
        return data

    def waiting(self):
        return len(self._bytes)


class MockConn(object):
    stream = None

    def __init__(self, mybytes):
        self.stream = MockStream(mybytes)

    def write(self, mybytes):
        pass


class FauxClient(object):
    def __init__(self):
        self.reader_mode = {'ModeIdentifier': 'M4', 'MaxTari': 7250}


class TestROSpec(unittest.TestCase):
    def test_start(self):
        fx = FauxClient()
        rospec = sllurp.llrp.LLRPROSpec(fx, 1)
        rospec_str = repr(rospec)
        self.assertNotEqual(rospec_str, '')


class TestReaderEventNotification(unittest.TestCase):
    def test_decode(self):
        data = binascii.unhexlify('043f000000200ab288c900f600160080000c0004f8'
                                  '535baadaff010000060000')
        client = sllurp.llrp.LLRPClient(self, start_inventory=False)
        client.transport = MockConn('')
        client.dataReceived(data)


class TestDecodeROAccessReport (unittest.TestCase):
    _r = """
    043d0000002c4095892f00f000228d3005fb63ac1f3841ec88046781000186ce820004ec2ea8
    354c09880001043d0000002c4095893000f000228d300833b2ddd906c00000000081000186c6
    820004ec2ea8355af2880001043d0000002c4095893100f000228d3005fb63ac1f3841ec8804
    6781000186cf820004ec2ea8359791880001043d0000002c4095893200f000228d300833b2dd
    d906c00000000081000186c6820004ec2ea835a71c880001043d0000002c4095893300f00022
    8d3005fb63ac1f3841ec88046781000186ce820004ec2ea835e0ff880001043d0000002c4095
    893400f000228d300833b2ddd906c00000000081000186c6820004ec2ea835f3e0880001043d
    0000002c4095893500f000228d3005fb63ac1f3841ec88046781000186ce820004ec2ea83630
    49880001043d0000002c4095893600f000228d300833b2ddd906c00000000081000186c68200
    04ec2ea836400f880001043d0000002c4095893700f000228d3005fb63ac1f3841ec88046781
    000186ce820004ec2ea83679c8880001043d0000002c4095893800f000228d300833b2ddd906
    c00000000081000186c6820004ec2ea8368c76880001043d0000002c4095893900f000228d30
    0833b2ddd906c00000000081000186c6820004ec2ea836c617880001043d0000002c4095893a
    00f000228d3005fb63ac1f3841ec88046781000186ce820004ec2ea836d516880001043d0000
    002c4095893b00f000228d3005fb63ac1f3841ec88046781000186ce820004ec2ea8370ebf88
    0001043d0000002c4095893c00f000228d300833b2ddd906c00000000081000186c6820004ec
    2ea8372189880001043d0000002c4095893d00f000228d3005fb63ac1f3841ec880467810001
    86cf820004ec2ea8375b09880001043d0000002c4095893e00f000228d300833b2ddd906c000
    00000081000186c6820004ec2ea8376a40880001043d0000002c4095893f00f000228d3005fb
    63ac1f3841ec88046781000186cf820004ec2ea837a430880001043d0000002c4095894000f0
    00228d300833b2ddd906c00000000081000186c6820004ec2ea837b699880001043d00000037
    4095894100f0002d00f1001800901fb41f712ac9c37ab79d618173188324001a81000186ef82
    0004ec2ea8381f57880001043d0000002c4095894200f000228d3005fb63ac1f3841ec880467
    81000186cf820004ec2ea8383238880001043d0000002c4095894300f000228d300833b2ddd9
    06c00000000081000186c4820004ec2ea8384211880001043d0000002c4095894400f000228d
    300833b2ddd906c00000000081000186c4820004ec2ea8387c55880001043d0000002c409589
    4500f000228d3005fb63ac1f3841ec88046781000186cf820004ec2ea83892cf880001043d00
    00002c4095894600f000228d300833b2ddd906c00000000081000186c3820004ec2ea838cc76
    880001043d0000002c4095894700f000228d3005fb63ac1f3841ec88046781000186cf820004
    ec2ea838dbb3880001043d0000002c4095894800f000228d3005fb63ac1f3841ec8804678100
    0186cf820004ec2ea8395e67880001043d0000002c4095894900f000228d300833b2ddd906c0
    0000000081000186c3820004ec2ea8396d13880001043d0000002c4095894a00f000228d3005
    fb63ac1f3841ec88046781000186cf820004ec2ea83a3119880001043d0000002c4095894b00
    f000228d300833b2ddd906c00000000081000186c3820004ec2ea83a4389880001043d000000
    2c4095894c00f000228d300833b2ddd906c00000000081000186c3820004ec2ea83a7d2b8800
    01043d0000002c4095894d00f000228d3005fb63ac1f3841ec88046781000186cf820004ec2e
    a83a8c28880001043d0000002c4095894e00f000228d300833b2ddd906c00000000081000186
    c3820004ec2ea83ac551880001043d0000002c4095894f00f000228d3005fb63ac1f3841ec88
    046781000186cf820004ec2ea83ad450880001043d0000002c4095895000f000228d300833b2
    ddd906c00000000081000186c7820004ec2ea83b26ad880001043d0000002c4095895100f000
    228d3005fb63ac1f3841ec88046781000186cf820004ec2ea83b35eb880001043d0000002c40
    95895200f000228d3005fb63ac1f3841ec88046781000186cf820004ec2ea83b701d88000104
    3d0000002c4095895300f000228d300833b2ddd906c00000000081000186c7820004ec2ea83b
    7f2c880001043d0000002c4095895400f000228d3005fb63ac1f3841ec88046781000186cf82
    0004ec2ea83bb8d8880001043d0000002c4095895500f000228d300833b2ddd906c000000000
    81000186c7820004ec2ea83bcbc5880001043d0000002c4095895600f000228d300833b2ddd9
    06c00000000081000186c7820004ec2ea83c0566880001043d0000002c4095895700f000228d
    3005fb63ac1f3841ec88046781000186cf820004ec2ea83c1479880001043d0000002c409589
    5800f000228d3005fb63ac1f3841ec88046781000186cf820004ec2ea83c4e47880001043d00
    00002c4095895900f000228d300833b2ddd906c00000000081000186c7820004ec2ea83c5d92
    880001043d0000002c4095895a00f000228d3005fb63ac1f3841ec88046781000186cf820004
    ec2ea83c9699880001043d0000002c4095895b00f000228d300833b2ddd906c0000000008100
    0186c7820004ec2ea83ca950880001"""
    _binr = None
    _client = None
    _tags_seen = 0

    def tagcb(self, llrpmsg):
        self._tags_seen += 1

    def setUp(self):
        self._r = self._r.rstrip().lstrip().replace('\n', '').replace(' ', '')
        self._binr = hex_to_bytes(self._r)
        self.assertEqual(len(self._r), 3982)
        self.assertEqual(len(self._binr), 1991)
        self._mock_conn = MockConn(self._binr)
        logger.debug('%d bytes waiting', self._mock_conn.stream.waiting())
        self._client = sllurp.llrp.LLRPClient(self, start_inventory=False)
        self._client.transport = MockConn('')
        self._client.addMessageCallback('RO_ACCESS_REPORT', self.tagcb)

    def test_start(self):
        """Parse the above pile of bytes into a series of LLRP messages."""
        self._client.state = sllurp.llrp.LLRPClient.STATE_INVENTORYING
        self._client.dataReceived(self._binr)
        self.assertEqual(self._tags_seen, 45)

    def tearDown(self):
        pass


class TestEncodings(unittest.TestCase):
    tagReportContentSelector = {
        'EnableROSpecID': False,
        'EnableSpecIndex': False,
        'EnableInventoryParameterSpecID': False,
        'EnableAntennaID': True,
        'EnableChannelIndex': False,
        'EnablePeakRRSI': True,
        'EnableFirstSeenTimestamp': True,
        'EnableLastSeenTimestamp': True,
        'EnableTagSeenCount': True,
        'EnableAccessSpecID': False}

    def test_roreportspec(self):
        par = {'ROReportTrigger': 'Upon_N_Tags_Or_End_Of_ROSpec',
               'N': 1}
        par['TagReportContentSelector'] = self.tagReportContentSelector
        sllurp.llrp_proto.encode_ROReportSpec(par)

    def test_tagreportcontentselector(self):
        par = self.tagReportContentSelector
        data = sllurp.llrp_proto.encode_TagReportContentSelector(par)
        self.assertEqual(len(data), 48 / 8)
        ty = int(binascii.hexlify(data[0:2]), 16) & (2**10 - 1)
        self.assertEqual(ty, 238)
        length = int(binascii.hexlify(data[2:4]), 16)
        self.assertEqual(length, len(data))
        flags = int(binascii.hexlify(data[4:]), 16) >> 6
        self.assertEqual(flags, 0b0001011110)


class TestMessageStruct(unittest.TestCase):
    s = sllurp.llrp_proto.Message_struct

    def test_can_encode_or_decode(self):
        for msg_name, msg_struct in self.s.items():
            self.assertIsInstance(msg_struct, dict)
            self.assertTrue('decode' in msg_struct or 'encode' in msg_struct)
            if 'decode' in msg_struct:
                self.assertTrue(callable(msg_struct['decode']))
            if 'encode' in msg_struct:
                self.assertTrue(callable(msg_struct['encode']))

    def test_has_fields(self):
        for msg_name, msg_struct in self.s.items():
            self.assertIsInstance(msg_struct, dict)
            self.assertIn('fields', msg_struct)
            self.assertIsInstance(msg_struct['fields'], list)

    def test_unique_types(self):
        d = {}
        for msg_name, msg_struct in self.s.items():
            self.assertIn('type', msg_struct)
            self.assertIsInstance(msg_struct['type'], int)
            self.assertNotIn(msg_struct['type'], d)
            d[msg_struct['type']] = True


if __name__ == '__main__':
    unittest.main()
