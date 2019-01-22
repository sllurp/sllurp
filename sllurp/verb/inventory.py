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
from sllurp.verb.http_server import httpServer
from apscheduler.schedulers.background import BackgroundScheduler
start_time = None
sched = BackgroundScheduler()
numtags = 0
logger = logging.getLogger(__name__)
logging.getLogger('apscheduler.executors.default').setLevel(logging.WARNING)
client = None
topic = None
http = None
tagList = []
tag_age_interval = 10 # 2 secs in micro seconds
def finish(*args):
    runtime = monotonic() - start_time
    logger.info('total # of tags seen: %d (%d tags/second)', numtags,
                numtags/runtime)
    if reactor.running:
        reactor.stop()

def shutdown(factory,http):
    if http:
        logger.info("stopping http")
        http.stopServer()
    if client:
        client.disconnect()
    return factory.politeShutdown()

def tag_report_cb(llrp_msg):
    """Function to run each time the reader reports seeing tags."""
    global numtags
    payload = llrp_msg.msgdict['RO_ACCESS_REPORT']['TagReportData']
    if len(payload):
        tags = pprint.pformat(payload).replace('\'','\"')
        tags = tags.replace('b\"','\"')
        logger.debug('saw tag(s): %s', payload)
        if http:
            if "EPC-96" in payload:
                epc = payload.get('EPC-96').decode('ascii')
            elif "EPCData" in payload:
                if 'EPC-96' in payload.get("EPCData"):
                    epc = payload["EPCData"]['EPC-96'].decode('ascii')
                elif 'EPC' in payload.get("EPCData"):
                    epc = payload["EPCData"]['EPC'].decode('ascii')
            tag = {
                'id' : epc,
                'timestamp': payload['LastSeenTimestampUTC'][0]
            }
            addToTagList(tag)
        # for tag in tags:
        #     numtags += tag['TagSeenCount'][0]
        if (client and topic ):
            logger.info("sending mqtt")
            client.publish(topic, payload=(tags), qos=0, retain=False)
        logger.info(tagList)
    else:
        logger.info('no tags seen')
        logger.info(tagList)
        return

def addToTagList(tag):
    global tagList
    foundTag,_ = listSearch(tag['id'],'id',tagList)
    logger.info(foundTag)
    if foundTag:
        foundTag['timestamp'] = tag['timestamp']
    else:
        tagList.append(tag)
    
def cleanTagList():
    global tagList
    #remove old tags
    scale_factor = 1000000 #seconds to microseconds
    for index, foundTag in enumerate(tagList):
        if abs(time.time() * scale_factor - foundTag['timestamp']) > tag_age_interval * scale_factor:
            logger.info("delete old tag")
            del tagList[index]

def listSearch(name,key,lst):
    for index, item in enumerate(lst):
        if item[key] == name:
            return item, index
    return False,False

def on_connect(client, userdata, flags, rc):
    print("Connected to MQTT BROKER with result code "+str(rc))

def main(args):
    global start_time
    global tag_age_interval
    global http
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
            'EnableChannelIndex': True,
            'EnablePeakRSSI': False,
            'EnableFirstSeenTimestamp': False,
            'EnableLastSeenTimestamp': True,
            'EnableTagSeenCount': True,
            'EnableAccessSpecID': False
        },
        impinj_extended_configuration=args.impinj_extended_configuration,
        impinj_search_mode=args.impinj_search_mode,
        impinj_tag_content_selector=None,
        http_port = args.http_port,
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
        if args.mqtt_password is not None and args.mqtt_username is not None:
            print("Starting secure mqtt: " + args.mqtt_password + " " + args.mqtt_username)
            client.username_pw_set(args.mqtt_username, args.mqtt_password)
        client.connect(args.mqtt_broker, args.mqtt_port, 60)
        client.loop_start()
        client.on_connect = on_connect
        topic = args.mqtt_topic
        if(args.mqtt_status_topic):
            factory_args['mqtt_client'] = client
            factory_args['mqtt_status_topic'] = args.mqtt_status_topic
            factory_args['mqtt_status_interval'] = args.mqtt_status_interval
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

    # start runtime measurement to determine rates
    start_time = monotonic()

    # catch ctrl-C and stop inventory before disconnecting
    reactor.addSystemEventTrigger('before', 'shutdown', shutdown, fac, http)

    if(args.http_server):
        tag_age_interval = args.tag_age_interval
        http = httpServer(tagList,args.http_port)
        sched.add_job(cleanTagList, 'interval', seconds=tag_age_interval)
        sched.start()
        http.startServer()

    reactor.run()
