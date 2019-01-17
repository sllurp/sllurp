#!/usr/bin/env python
#
# main.py - Example of using Sllurp with Tornado
#
# Copyright (C) 2014 Johnny Sheeley
# Copyright (C) 2013-2018 Benjamin Ransford <ransford@cs.washington.edu>
# Copyright (C) 2019 Florent Viard <fviard@cxignited.com>
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
#
#
"""Sllurp/Tornado Example

This file contains an example showing how to use Sllurp with Tornado
to update a web page via websockets when rfid tags are seen.
"""

import sys
import os
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..', '..')))

from argparse import ArgumentParser
from logging import getLogger, INFO, Formatter, StreamHandler, WARN

from tornado.escape import json_decode
from tornado.ioloop import IOLoop
from tornado.template import Loader
from tornado.web import RequestHandler, Application
from tornado.websocket import WebSocketClosedError, WebSocketHandler

from sllurp.llrp import LLRP_DEFAULT_PORT, LLRPReaderConfig, LLRPReaderClient
from sllurp.llrp_proto import Modulation_DefaultTari
from sllurp.log import get_logger


logger = get_logger('sllurp')

tornado_main_ioloop = None


def setup_logging():
    logger.setLevel(INFO)
    logFormat = '%(asctime)s %(name)s: %(levelname)s: %(message)s'
    formatter = Formatter(logFormat)
    handler = StreamHandler()
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    stream_handler_warn = StreamHandler()
    stream_handler_warn.setLevel(WARN)
    stream_handler_warn.setFormatter(formatter)

    access_log = getLogger("tornado.access")
    access_log.addHandler(stream_handler_warn)

    app_log = getLogger("tornado.application")
    app_log.addHandler(handler)

    gen_log = getLogger("tornado.general")
    gen_log.addHandler(handler)


class DefaultHandler(RequestHandler):
    def get(self):
        loader = Loader(os.path.dirname(__file__))
        template = loader.load("index.html")
        self.write(template.generate())


class MyWebSocketHandler(WebSocketHandler):
    _connected_clients = 0
    _listeners = set([])

    @classmethod
    def dispatch_tags(cls, tags):
        for listener in cls._listeners:
            try:
                listener.update_rfid(tags)
            except Exception as exc:
                logger.warning("Error sending tags to a client: %s", str(exc))

    def open(self):
        MyWebSocketHandler._connected_clients += 1
        MyWebSocketHandler._listeners.add(self)
        logger.debug("WebSocket client connected (total: %d)",
                     self._connected_clients)

    def on_message(self, message):
        try:
            data = json_decode(message)
            logger.info(data)
        except ValueError:
            logger.info('error loading json: {}'.format(message))

    def on_close(self):
        MyWebSocketHandler._connected_clients -= 1
        MyWebSocketHandler._listeners.remove(self)
        logger.debug("WebSocket client disconnected (total: %d)",
                     self._connected_clients)

    def update_rfid(self, tags):
        if self._connected_clients > 0:
            try:
                payload = {'tags': tags}
                self.write_message(payload)
                # logger.debug('websocket write: {}'.format(pformat(payload)))
            except WebSocketClosedError:
                logger.debug('attempting to send websocket message with no '
                             'connected clients')

def convert_to_unicode(obj):
    """
    Tornado dict to json expects unicode strings in dict.
    """
    if isinstance(obj, dict):
        return {
            convert_to_unicode(key):
                convert_to_unicode(value) for key, value in obj.items()
        }
    elif isinstance(obj, list):
        return [convert_to_unicode(element) for element in obj]
    elif isinstance(obj, bytes):
        return obj.decode('utf-8')
    else:
        return obj


def tag_seen_callback(reader, tags):
    """Function to run each time the reader reports seeing tags."""
    if tags:
        tags = convert_to_unicode(tags)
        tornado_main_ioloop.add_callback(MyWebSocketHandler.dispatch_tags,
                                         tags)


def parse_args():
    parser = ArgumentParser(description='Simple RFID Reader Inventory')
    parser.add_argument('host', help='hostname or IP address of RFID reader',
                        nargs='*')
    parser.add_argument('-p', '--port', default=LLRP_DEFAULT_PORT, type=int,
                        help='port to connect to (default {})'
                        .format(LLRP_DEFAULT_PORT))
    parser.add_argument('-n', '--report-every-n-tags', default=1, type=int,
                        dest='every_n', metavar='N',
                        help='issue a TagReport every N tags')
    parser.add_argument('-a', '--antennas', default='1',
                        help='comma-separated list of antennas to enable')
    parser.add_argument('-X', '--tx-power', default=0, type=int,
                        dest='tx_power',
                        help='Transmit power (default 0=max power)')
    parser.add_argument('-M', '--modulation', default='M8',
                        help='modulation (default M8)')
    parser.add_argument('-T', '--tari', default=0, type=int,
                        help='Tari value (default 0=auto)')
    parser.add_argument('-s', '--session', type=int, default=2,
                        help='Gen2 session (default 2)')
    parser.add_argument('--mode-identifier', type=int,
                        help='ModeIdentifier value')
    parser.add_argument('-P', '--tag-population', type=int, default=4,
                        help="Tag Population value (default 4)")
    parser.add_argument('--impinj-search-mode', choices=['1', '2'],
                        help=('Impinj extension: inventory search mode '
                              '(1=single, 2=dual)'))
    parser.add_argument('--impinj-reports', type=bool, default=False,
                        help='Enable Impinj tag report content (Phase angle, '
                             'RSSI, Doppler)')
    return parser.parse_args()


def main(args):
    global tornado_main_ioloop
    setup_logging()

    # Set up tornado the global var keeping the current tornado main loop
    tornado_main_ioloop = IOLoop.current()

    if not args.host:
        logger.info('No readers specified.')
        return 0

    # Set up web server
    application = Application([(r"/", DefaultHandler),
                               (r"/ws", MyWebSocketHandler)])
    application.listen(8888)


    # Special case default Tari values
    tari = args.tari
    if args.modulation in Modulation_DefaultTari:
        t_suggested = Modulation_DefaultTari[args.modulation]
        if args.tari:
            logger.warn('recommended Tari for %s is %d', args.modulation,
                        t_suggested)
        else:
            tari = t_suggested
            logger.info('selected recommended Tari of %d for %s', args.tari,
                        args.modulation)

    enabled_antennas = [int(x.strip()) for x in args.antennas.split(',')]
    factory_args = dict(
        report_every_n_tags=args.every_n,
        antennas=enabled_antennas,
        tx_power=args.tx_power,
        modulation=args.modulation,
        tari=tari,
        session=args.session,
        mode_identifier=args.mode_identifier,
        tag_population=args.tag_population,
        start_inventory=True,
        tag_content_selector={
            'EnableROSpecID': True,
            'EnableSpecIndex': True,
            'EnableInventoryParameterSpecID': True,
            'EnableAntennaID': True,
            'EnableChannelIndex': True,
            'EnablePeakRSSI': True,
            'EnableFirstSeenTimestamp': True,
            'EnableLastSeenTimestamp': True,
            'EnableTagSeenCount': True,
            'EnableAccessSpecID': True,
            'C1G2EPCMemorySelector': {
                'EnableCRC': True,
                'EnablePCBits': True,
            }
        },
        impinj_search_mode=args.impinj_search_mode,
        impinj_tag_content_selector=None,
    )
    if args.impinj_reports:
        factory_args['impinj_tag_content_selector'] = {
            'EnableRFPhaseAngle': True,
            'EnablePeakRSSI': True,
            'EnableRFDopplerFrequency': True
        }

    reader_clients = []
    for host in args.host:
        if ':' in host:
            host, port = host.split(':', 1)
            port = int(port)
        else:
            port = args.port

        config = LLRPReaderConfig(factory_args)
        reader = LLRPReaderClient(host, port, config)
        reader.add_tag_report_callback(tag_seen_callback)

        reader_clients.append(reader)

    try:
        for reader in reader_clients:
            reader.connect()
        tornado_main_ioloop.start()
    finally:
        logger.info("Exit detected! Stopping readers...")
        for reader in reader_clients:
            try:
                reader.disconnect()
            except:
                logger.exception("Error during disconnect. Ignoring...")

    while True:
        # Join all threads using a timeout so it doesn't block
        # Filter out threads which have been joined or are None
        alive_readers = [reader
                         for reader in reader_clients if reader.is_alive()]
        if not alive_readers:
            break
        for reader in alive_readers:
            reader.join(1)


if __name__ == '__main__':
    # Load Sllurp config
    cmd_args = parse_args()
    main(cmd_args)
