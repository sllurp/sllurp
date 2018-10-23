#!/bin/bash

sllurp direction --field_of_view 0 --enable_sector_id '[2,4,8]' -r -X 81 -t 6 --tag_age_interval 4 --mqtt-broker localhost --mqtt-topic llrp/1 10.10.90.39

