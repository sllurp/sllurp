#!/usr/bin/env python3

import bitstring
import pprint

ap_strings = ("00 f0 00 1f 8d 35 e0 17 00 43 ba bb ce 00 00 14 1d 81 00 01 \
86 d8 82 00 03 dc 30 8b 3e fa 9f",
              "00 f0 00 1f 8d 35 e0 17 00 43 ba bb ce 00 00 14 25 81 00 01 \
86 d5 82 00 03 dc 30 8b 48 08 e2",
              "00 f0 00 1f 8d 35 e0 17 00 43 ba bb ce 00 00 14 1d 81 00 01 \
86 d9 82 00 03 dc 30 8b 4e 44 9a",
              "00 f0 00 1f 8d 35 e0 17 00 43 ba bb ce 00 00 14 1d 81 00 01 \
86 db 82 00 03 dc 30 8b 57 12 ee")

def get_epc (ap, offset=0):
    epc = None
    print(ap[offset+6:offset+16].uint)
    if ap[offset+6:offset+16].uint == 241:
        epc_fieldlen = ap[offset+16+16:offset+16+16+16].uint
        epc = 'EPCData field of length {}'.format(epclen)
    elif ap[offset+1:offset+8].uint == 13:
        epc_fieldlen = 96 + 8
        epc = 'EPC-96: {}'.format(ap[offset+8:offset+8+96].hex)
    return (epc, epc_fieldlen)

def get_params (ap):
    params = {}
    ofs = 0
    while ofs < len(ap):
        # 1 bit of "1"
        # 7 bits of parameter ID
        one = ap[ofs] # throwaway
        ptype = ap[ofs+1:ofs+8].uint
        ofs += 8
        if ptype == 9:
            params['ROSpecID'] = ap[ofs:ofs+32].uint
            ofs += 32
            continue
        elif ptype == 14:
            params['SpecIndex'] = ap[ofs:ofs+16].uint
            ofs += 16
            continue
        elif ptype == 10:
            params['InventoryParameterSpecID'] = ap[ofs:ofs+16].uint
            ofs += 16
            continue
        elif ptype == 1:
            params['AntennaID'] = ap[ofs:ofs+16].uint
            ofs += 16
            continue
        elif ptype == 6:
            params['PeakRSSI'] = ap[ofs:ofs+8].int
            ofs += 8
            continue
        elif ptype == 7:
            params['ChannelIndex'] = ap[ofs:ofs+16].uint
            ofs += 16
            continue
        elif ptype == 2:
            # us since epoch
            params['FirstSeenTimestampUTC'] = ap[ofs:ofs+64].uint
            ofs += 64
            continue
        elif ptype == 3:
            # us since boot
            params['FirstSeenTimestampUptime'] = ap[ofs:ofs+64].uint
            ofs += 64
            continue
        elif ptype == 4:
            # us since epoch
            params['LastSeenTimestampUTC'] = ap[ofs:ofs+64].uint
            ofs += 64
            continue
        elif ptype == 5:
            # us since boot
            params['LastSeenTimestampUptime'] = ap[ofs:ofs+64].uint
            ofs += 64
            continue
        elif ptype == 8:
            params['TagSeenCount'] = ap[ofs:ofs+16].uint
            ofs += 16
            continue
        elif ptype == 15:
            params['ClientRequestOpSpecResult'] = ap[ofs:ofs+16].uint
            ofs += 16
            continue
        elif ptype == 16:
            params['AccessSpecID'] = ap[ofs:ofs+32].uint
            ofs += 32
            continue
    return params


def parts (ap):
    ret = {}
    ret['Type'] = ap[6:16].uint
    ret['Length'] = ap[16:32].uint
    epc, epc_fieldlen = get_epc(ap, offset=32)
    ret['EPC'] = epc
    ret['Params'] = get_params(ap[32+epc_fieldlen:])
    return ret

for ap in ap_strings:
    as_bits = bitstring.BitString(hex=ap)
    print('Hex: {}'.format(as_bits.hex))
    #print('Bin: {}'.format(as_bits.bin))
    pprint.pprint(parts(as_bits))
