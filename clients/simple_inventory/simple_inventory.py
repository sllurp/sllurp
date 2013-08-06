#!/usr/bin/env python

# simple_inventory.py - execute a simple inventory command
#
# Copyright (C) 2009 Rodolfo Giometti <giometti@linux.it>
# Copyright (C) 2009 CAEN RFID <support.rfid@caen.it>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

import sys, getopt, logging, time
from llrp_proto import *

#
# Local functions
#

def out(x):
    sys.stdout.write(str(x))

def print_event(connection, msg):
    print 'New event:'
    print msg

#
# Usage function
#

def usage():
        print 'usage: %s [<options>] host' % sys.argv[0]
        print 'where <options> are:\n'                  \
                '\t-h - show this help message\n'       \
                '\t-d - enable debugging messages\n'
        sys.exit(1)

#
# main
#

# Check command line
optlist, list = getopt.getopt(sys.argv[1:], ':hd')
for opt in optlist:
        if opt[0] == '-h':
                usage()

        if opt[0] == '-d':
                llrp_set_logging(logging.DEBUG)

if len(list) < 1:
        usage()
host = list[0]

# Connect with remote LLRPd
out('connecting with ' + host +'... ')
try:
    server = LLRPdConnection(host, event_cb = print_event)
except LLRPResponseError, ret:
    print 'fail: %s' % ret
    sys.exit(1)
print 'done'

# Get reader capabilities
out('asking for reader capabilities... ')
try:
    cap = server.get_capabilities('LLRP Capabilities')
except LLRPResponseError, ret:
    print 'fail: %s' % ret
    sys.exit(1)
print 'done'
print 'capabilities are:'
print cap

# Delete all existing ROSpecs
out('deleting all existing ROSpecs... ')
try:
    server.delete_all_rospec()
except LLRPResponseError, ret:
    print 'fail: %s' % ret
    sys.exit(1)
print 'done'

# Create a ROSpec
print 'using ROSpec:'
rospec = LLRPROSpec(123)
print rospec

# Add ROSpec
out('adding ROSpec... ')
try:
    rospec.add(server)
except LLRPResponseError, ret:
    print 'fail: %s' % ret
    server.close()
    sys.exit(1)
print 'done'

# Enable ROSpec
out('enabling ROSpec... ')
try:
    rospec.enable(server)
except LLRPResponseError, ret:
    print 'fail: %s' % ret
    server.close()
    sys.exit(1)
else:
        print 'done'

# Start ROSpec
out('starting ROSpec... ')
try:
    rospec.start(server)
except LLRPResponseError, ret:
    print 'fail: %s' % ret
    server.close()
    sys.exit(1)
else:
    print 'done'

print 'waiting 5 seconds... '
time.sleep(5)

# Stop ROSpec
out('stopping ROSpec... ')
try:
    rospec.stop(server)
except LLRPResponseError, ret:
    print 'fail: %s' % ret
    server.close()
    sys.exit(1)
else:
        print 'done'

# Disable ROSpec
out('disabling ROSpec... ')
try:
    rospec.disable(server)
except LLRPResponseError, ret:
    print 'fail: %s' % ret
    server.close()
    sys.exit(1)
else:
        print 'done'

# Delete ROSpec
out('deleting ROSpec... ')
try:
    rospec.delete(server)
except LLRPResponseError, ret:
    print 'fail: %s' % ret
    server.close()
    sys.exit(1)
else:
        print 'done'

# Close connection
out('disconnecting from ' + host + '... ')
server.close()
print 'done'
