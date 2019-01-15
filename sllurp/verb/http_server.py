from threading import Thread
from flask import Flask
from flask_jsonrpc import JSONRPC
from flask_api import status
import json
app = Flask(__name__)
jsonrpc = JSONRPC(app, '/jsonrpc')
#payload is a list of dict
payload = []
error = False

class httpServer:
    def __init__(self,data,port):
        global payload
        payload = data
        self.port = port
        self.thread = Thread(target = self.startThread)

    def startThread(self):
        app.run(host='0.0.0.0', port=self.port)

    def startServer(self):
        self.thread.daemon = True
        self.thread.start()

    def stopServer(self):
        self.thread.daemon = False
        print("shutting down server")

@app.route("/gettags")
def httpGetTags():
    if error:
        return "Reader Connection Failed",status.HTTP_503_SERVICE_UNAVAILABLE
    else:
        data = [item['id'] for item in payload]
        return json.dumps(data)

@app.route("/deletetags")
def httpDeleteTags():
    if error:
        return "Reader Connection Failed",status.HTTP_503_SERVICE_UNAVAILABLE
    else:
        del payload[:]
        return "TagList Deleted"

@app.route("/setConnectionError")
def httpSetReaderError():
    global error
    error = True
    return "set reader connection failed"

@app.route("/removeConnectionError")
def htttpRemoveReaderError():
    global error
    error = False
    return "reader connected"

@jsonrpc.method('gettags')
def jsonRPCGetTags():
    if error:
        return "Reader Connection Failed",status.HTTP_503_SERVICE_UNAVAILABLE
    else:
        data = [item['id'] for item in payload]
        return json.dumps(data)

@jsonrpc.method('deletetags')
def jsonRPCDeleteTags():
    if error:
        return "Reader Connection Failed",status.HTTP_503_SERVICE_UNAVAILABLE
    else:
        del payload[:]
        return u'TagList Deleted'