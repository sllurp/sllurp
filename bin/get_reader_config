#!/bin/sh

if [ $# -ne 1 ]; then
	echo "Usage: $(basename $0) reader_hostname" 2>&1
	exit 1
fi

READER="$1"; shift
RUSER=root

echo "copy \"impinj\" to the clipboard for pasting below..."
ssh "${RUSER}@${READER}" show rfid llrp rospec 0 > rospec_0.xml
ssh "${RUSER}@${READER}" show rfid llrp accessspec 0 > accessspec_0.xml
ssh "${RUSER}@${READER}" show rfid llrp capabilities > capabilities.xml
ssh "${RUSER}@${READER}" show rfid llrp config > config.xml
ssh "${RUSER}@${READER}" show rfid llrp inbound > inbound.xml
ssh "${RUSER}@${READER}" show rfid llrp summary > summary.xml
