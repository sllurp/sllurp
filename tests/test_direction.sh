#!/bin/bash

sllurp direction --enable_sector_id '[2,4,6]' -r -X 81 -t 4 --tag_age_interval 10 --mqtt-broker localhost --mqtt-topic llrp/1 10.10.31.170 
