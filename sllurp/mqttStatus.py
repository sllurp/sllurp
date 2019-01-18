import sys
import json
import datetime
import time
import socket
import platform as p
import ctypes
import struct

class MqttStatus: 
  def __init__(self,mode,topic="test"):
    self.baseStatus = {
      "date":{
        "raw":"",
        "local":"",
        "epoch":0,
        "offset":0
      },
      "os":{
        "hostname": socket.gethostname(),
        "platform":p.platform(),
      },
      "uptime": 0,
      "llrp":{
        "mode" : mode,
      }
    }
    self.readerStatus = {}
    self.status = {} #ok,degraded
    self.topic = topic
    
  def generateStatus(self):
    self.baseStatus["date"]["raw"] = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    utc_offset_sec = time.altzone if time.localtime().tm_isdst else time.timezone
    utc_offset = datetime.timedelta(seconds=-utc_offset_sec)
    self.baseStatus["date"]["local"] = datetime.datetime.now().replace(tzinfo=datetime.timezone(offset=utc_offset)).isoformat()
    self.baseStatus["date"]["offset"] = int(-utc_offset_sec / 3600)
    self.baseStatus["date"]["epoch"] = int(time.time())
    self.baseStatus["uptime"] = int(self.uptime())
    self.baseStatus["llrp"]["antenna"] = self.readerStatus
    self.baseStatus["llrp"]["status"] = "ok"
    self.baseStatus["llrp"]["reason"] = ""
    for ant, status in self.readerStatus.items():
      if status == "disconnected":
        self.baseStatus["llrp"]["status"] = "degraded"
        self.baseStatus["llrp"]["reason"] = self.baseStatus["llrp"]["reason"] + str(ant) + " disconnected" + ", "
    return json.dumps(self.baseStatus)

  def uptime(self):
      libc = ctypes.CDLL('libc.so.6')
      buf = ctypes.create_string_buffer(4096) # generous buffer to hold
                                              # struct sysinfo
      if libc.sysinfo(buf) != 0:
          print('failed')
          return -1

      uptime = struct.unpack_from('@l', buf.raw)[0]
      return uptime

  def setReaderStatus(self,readerIP,status):
      self.readerStatus[readerIP] = status

  def setTopic(self,topic):
    self.topic = topic
  
  def getTopic(self):
    return self.topic