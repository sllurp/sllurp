#!/usr/bin/env python

# reader_test.py - test if an LLRP reader is compliant to the protocol
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

import sys, getopt, logging
from llrp_proto import *

#
# Local functions
#

def out(x):
        sys.stdout.write(str(x))

#
# Connection tests
#

def simple_connection(host):
    out('doing \'%s\' test... ' % func())

    try:
        server = LLRPdConnection(host)
    except:
        print 'failed!'
        ret = 1
    else:
        print 'pass'
        ret = 0

    server.close()

    return ret

def double_connection(host):
    out('doing \'%s\' test... ' % func())

    # First connection should success
    try:
        server1 = LLRPdConnection(host)
    except:
        print 'failed!'
        ret = 1

    # But not the second one!
    try:
        server2 = LLRPdConnection(host)
    except LLRPError, ret:
        print 'pass'
        ret = 0
    else:
        print 'failed!'
        ret = 1

    server1.close()

    return ret

#
# Do it all
#

tests = {
    'Connection tests' : [
        simple_connection,
        double_connection,
    ]
}

def do_all(host):
    print 'running LLRP tests'
    print 'parameters are:'
    print '\thost = %s' % host
    print

    x = 1
    y = 1
    ok = True
    for test in tests:
        print '--- %s ---' % test
        for func in tests[test]:
            out('%d.%d) ' % (x, y))
            ret = func(host)
            if ret:
                ok = False

            y += 1
        x += 1
    print

    if not ok:
        print 'at least one test failed!'
        sys.exit(1)

    print 'all tests passed!'
    sys.exit(0)

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
# Main
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

# Do LLRP tests
do_all(host)
