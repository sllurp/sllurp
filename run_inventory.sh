#!/bin/bash

python3 -m venv .venv &&
source .venv/bin/activate &&
pip3 install wheel
pip3 install . &&
sllurp inventory -n 1 -s 2 -P 32 ${1+"$@"} -M WISP5 --impinj-search-mode 2 192.168.10.102
deactivate &&
rm -rf .venv
