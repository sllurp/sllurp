#!/bin/bash

sllurp location -r --mode-identifier 1003 -X 81 -t 20 --compute_window 5 --tag_age_interval 30 --mqtt-broker localhost --mqtt-topic llrp/1 10.10.31.170
