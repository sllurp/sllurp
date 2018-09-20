from threading import Thread
from flask import Flask
from flask_jsonrpc import JSONRPC
import json
app = Flask(__name__)
jsonrpc = JSONRPC(app, '/jsonrpc')
#payload is a list of dict
payload = []

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
    data = [item['id'] for item in payload]
    return json.dumps(data)
  
@jsonrpc.method('gettags')
def jsonRPCGetTags():
    return json.dumps(payload)