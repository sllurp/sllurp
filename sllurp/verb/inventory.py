"""Inventory command.
"""

from __future__ import print_function, division
import logging
import pprint
import time
from twisted.internet import reactor, defer
import paho.mqtt.client as mqtt
import json

from sllurp.util import monotonic
from sllurp.llrp import LLRPClientFactory
from sllurp.llrp_proto import Modulation_DefaultTari

start_time = None

numtags = 0
logger = logging.getLogger(__name__)
client = None
topic = None


def finish(*args):
    runtime = monotonic() - start_time
    logger.info('total # of tags seen: %d (%d tags/second)', numtags,
                numtags/runtime)
    if reactor.running:
        reactor.stop()


def shutdown(factory):
    if client:
      client.disconnect()
    return factory.politeShutdown()


def tag_report_cb(llrp_msg):
    """Function to run each time the reader reports seeing tags."""
    global numtags
    tags = llrp_msg.msgdict['RO_ACCESS_REPORT']['TagReportData']
    if len(tags):
        payload = pprint.pformat(tags).replace('\'','\"')
        payload = payload.replace('b\"','\"')
        logger.info('saw tag(s): %s', payload)
        # for tag in tags:
        #     numtags += tag['TagSeenCount'][0]
        if (client and topic ):
            logger.info("sending mqtt")
            client.publish(topic, payload=(payload), qos=0, retain=False)
    else:
        logger.info('no tags seen')
        return

def on_connect(client, userdata, flags, rc):
    print("Connected to MQTT BROKER with result code "+str(rc))

def main(args):
    global start_time

    if not args.host:
        logger.info('No readers specified.')
        return 0

    # special case default Tari values
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
    antmap = {
        host: {
            str(ant): 'Antenna {}'.format(ant) for ant in enabled_antennas
        } for host in args.host
    }
    logger.info('Antenna map: %s', antmap)

    # d.callback will be called when all connections have terminated normally.
    # use d.addCallback(<callable>) to define end-of-program behavior.
    d = defer.Deferred()
    d.addCallback(finish)

    factory_args = dict(
        onFinish=d,
        duration=args.time,
        report_every_n_tags=args.every_n,
        antenna_dict=antmap,
        tx_power=args.tx_power,
        modulation=args.modulation,
        tari=tari,
        session=args.session,
        mode_identifier=args.mode_identifier,
        tag_population=args.population,
        start_mode="inventory",
        reset_on_connect=True,
        disconnect_when_done=args.time and args.time > 0,
        reconnect=args.reconnect,
        tag_content_selector={
            'EnableROSpecID': False,
            'EnableSpecIndex': False,
            'EnableInventoryParameterSpecID': False,
            'EnableAntennaID': False,
            'EnableChannelIndex': False,
            'EnablePeakRSSI': False,
            'EnableFirstSeenTimestamp': False,
            'EnableLastSeenTimestamp': False,
            'EnableTagSeenCount': False,
            'EnableAccessSpecID': False
        },
        impinj_extended_configuration=args.impinj_extended_configuration,
        impinj_search_mode=args.impinj_search_mode,
        impinj_tag_content_selector=None,
    )
    if args.impinj_reports:
        factory_args['impinj_tag_content_selector'] = {
            'EnableRFPhaseAngle': True,
            'EnablePeakRSSI': False,
            'EnableRFDopplerFrequency': False
        }
    if(args.mqtt_broker):
        global client
        global topic
        client = mqtt.Client()
        client.connect(args.mqtt_broker, args.mqtt_port, 60)
        client.loop_start()
        client.on_connect = on_connect
        topic = args.mqtt_topic
    fac = LLRPClientFactory(**factory_args)

    # tag_report_cb will be called every time the reader sends a TagReport
    # message (i.e., when it has "seen" tags).
    fac.addTagReportCallback(tag_report_cb)

    for host in args.host:
        if ':' in host:
            host, port = host.split(':', 1)
            port = int(port)
        else:
            port = args.port
        reactor.connectTCP(host, port, fac, timeout=3)

    # catch ctrl-C and stop inventory before disconnecting
    reactor.addSystemEventTrigger('before', 'shutdown', shutdown, fac)

    # start runtime measurement to determine rates
    start_time = monotonic()

    reactor.run()
