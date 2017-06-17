'''
Tool used to parse SGTIN-96 hex string from RFID tags.

SGTIN Format (bits):
Header    Filter  Partition   Company Prefix  Item Reference  Serial
8         3       3           20-40           24-4            38

Documentation here:
http://www.gs1.org/sites/default/files/docs/tds/TDS_1_9_Standard.pdf

'''

'''
Table defining partition sizes for SGTIN-96
'''
SGTIN_96_PARTITION_MAP = {
    0: (40, 12, 4, 1),
    1: (37, 11, 7, 2),
    2: (34, 10, 10, 3),
    3: (30, 9, 14, 4),
    4: (27, 8, 17, 5),
    5: (24, 7, 20, 6),
    6: (20, 6, 24, 7)
}


def parse_sgtin_96(sgtin_96):
    '''Given a SGTIN-96 hex string, parse each segment.
    Returns a dictionary of the segments.'''

    if not sgtin_96:
        raise Exception('Pass in a value.')

    if not sgtin_96.startswith("30"):
        # not a sgtin, not handled
        raise Exception('Not SGTIN-96.')

    binary = "{0:020b}".format(int(sgtin_96, 16)).zfill(96)

    header = int(binary[:8], 2)
    tag_filter = int(binary[8:11], 2)

    partition = binary[11:14]
    partition_value = int(partition, 2)

    m, l, n, k = SGTIN_96_PARTITION_MAP[partition_value]

    company_start = 8 + 3 + 3
    company_end = company_start + m
    company_data = int(binary[company_start:company_end], 2)
    if company_data > pow(10, l):
        # can't be too large
        raise Exception('Company value is too large')
    company_prefix = str(company_data).zfill(l)

    item_start = company_end
    item_end = item_start + n
    item_data = binary[item_start:item_end]
    item_number = int(item_data, 2)
    item_reference = str(item_number).zfill(k)

    serial = int(binary[-38:], 2)

    return {
        "header": header,
        "filter": tag_filter,
        "partition": partition,
        "company_prefix": company_prefix,
        "item_reference": item_reference,
        "serial": serial
    }


def parse_sgtin_96_to_uri(sgtin_96):
    '''Given a SGTIN-96 hex string, parse each segment.
    Returns a tag URI string.'''
    tag_dict = parse_sgtin_96(sgtin_96)
    uri_template = ("urn:epc:id:sgtin:{company_prefix}."
                    "{item_reference}.{serial}")
    return uri_template.format(**tag_dict)
