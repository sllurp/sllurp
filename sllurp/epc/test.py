import unittest
import sgtin_96
import gtin
import logging

logLevel = logging.WARNING
logging.basicConfig(level=logLevel,
                    format='%(asctime)s %(name)s: %(levelname)s: %(message)s')
logger = logging.getLogger('sllurp')
logger.setLevel(logLevel)


class SGTIN_96_Tests(unittest.TestCase):

    def test_check_digit(self):
        self.assertEqual(gtin.calculate_check_digit("0846632485751"), 5)

    def test_check_digit_2(self):
        self.assertEqual(gtin.calculate_check_digit("084663228621"), 0)

    def test_check_digit_combined(self):
        self.assertEqual(gtin.combine_gtin_with_check_digit(
            "0846632485751"), "08466324857515")

    def test_check_digit_combined_2(self):
        self.assertEqual(gtin.combine_gtin_with_check_digit(
            "084663228621"), "0846632286210")

    def test_epc_96_decode(self):
        # input
        epc = "30204ed9496334000000006e"
        # output
        parsed_company_prefix = "084663228621"
        parsed_gtin_string = "0846632286210"
        parsed_serial = 110
        parsed_item_reference = '0'
        parsed_partition = '000'
        parsed_filter = 1
        parsed_header = 48

        # actually do it
        parsed = sgtin_96.parse_sgtin_96(epc)
        full_gtin = gtin.combine_gtin_with_check_digit(
            parsed["company_prefix"])

        self.assertEqual(parsed['serial'], parsed_serial)
        self.assertEqual(parsed['company_prefix'], parsed_company_prefix)
        self.assertEqual(parsed['item_reference'], parsed_item_reference)
        self.assertEqual(parsed['filter'], parsed_filter)
        self.assertEqual(parsed['partition'], parsed_partition)
        self.assertEqual(parsed['header'], parsed_header)

        self.assertEqual(full_gtin, parsed_gtin_string)

    def test_epc_96_decode_uri(self):
        epc = "30204ed9496334000000006e"
        uri = "urn:epc:id:sgtin:084663228621.0.110"
        self.assertEqual(sgtin_96.parse_sgtin_96_to_uri(epc), uri)


if __name__ == '__main__':
    unittest.main()
