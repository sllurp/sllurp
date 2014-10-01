# Parsing EPC Data
EPC Tag Data Standard located here: [http://www.gs1.org/sites/default/files/docs/tds/TDS_1_9_Standard.pdf](http://www.gs1.org/sites/default/files/docs/tds/TDS_1_9_Standard.pdf)

## SGTIN-96 to GTIN
Replace tag_seen_callback in main README with the following:
```python
from sllurp.epc.sgtin_96 import parse_sgtin_96
from sllurp.epc.gtin import combine_gtin_with_check_digit

def tag_seen_callback(llrpMsg):
    tags = llrpMsg.msgdict.get('RO_ACCESS_REPORT', {}).get('TagReportData')
    if tags:
        for tag in tags:
            sgtin_96 = tag.get('EPC-96')
            tag = parse_sgtin_96(sgtin_96)
            company_prefix = tag["company_prefix"]
            full_gtin = combine_gtin_with_check_digit(company_prefix)
            print full_gtin
```
