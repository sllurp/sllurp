#!/bin/bash

python3 -m venv .venv &&
source .venv/bin/activate &&
pip3 install wheel &&
pip3 install . &&
sllurp inventory -s 0 -P 2 --impinj-fixed-freq --mode-identifier 0 --impinj-search-mode 2  192.168.0.100
deactivate &&
rm -rf .venv
