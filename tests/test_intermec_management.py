import base64
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from xml.etree import ElementTree as ET

import pytest

from sllurp.intermec_management import IntermecDCWSManager
from sllurp.reader_management import ReaderManagementError, create_reader_manager


WSDL11 = b'''<?xml version="1.0"?>
<wsdl:definitions xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/"
 xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
 xmlns:tns="urn:intermec:dcws" targetNamespace="urn:intermec:dcws">
 <wsdl:message name="GetConfigRequest"><wsdl:part name="p" element="tns:GetConfig"/></wsdl:message>
 <wsdl:message name="SetConfigRequest"><wsdl:part name="p" element="tns:SetConfig"/></wsdl:message>
 <wsdl:message name="FaultMeRequest"><wsdl:part name="p" element="tns:FaultMe"/></wsdl:message>
 <wsdl:message name="BadXMLRequest"><wsdl:part name="p" element="tns:BadXML"/></wsdl:message>
 <wsdl:portType name="DeviceConfigPortType">
  <wsdl:operation name="GetConfig"><wsdl:input message="tns:GetConfigRequest"/></wsdl:operation>
  <wsdl:operation name="SetConfig"><wsdl:input message="tns:SetConfigRequest"/></wsdl:operation>
  <wsdl:operation name="FaultMe"><wsdl:input message="tns:FaultMeRequest"/></wsdl:operation>
  <wsdl:operation name="BadXML"><wsdl:input message="tns:BadXMLRequest"/></wsdl:operation>
 </wsdl:portType>
 <wsdl:binding name="DeviceConfigBinding" type="tns:DeviceConfigPortType">
  <soap:binding style="document" transport="http://schemas.xmlsoap.org/soap/http"/>
  <wsdl:operation name="GetConfig"><soap:operation soapAction="urn:GetConfig"/></wsdl:operation>
  <wsdl:operation name="SetConfig"><soap:operation soapAction="urn:SetConfig"/></wsdl:operation>
  <wsdl:operation name="FaultMe"><soap:operation soapAction="urn:FaultMe"/></wsdl:operation>
  <wsdl:operation name="BadXML"><soap:operation soapAction="urn:BadXML"/></wsdl:operation>
 </wsdl:binding>
 <wsdl:service name="DeviceConfiguration">
  <wsdl:port name="DeviceConfigPort" binding="tns:DeviceConfigBinding">
   <soap:address location="http://different-host.invalid/dcws"/>
  </wsdl:port>
 </wsdl:service>
</wsdl:definitions>'''

WSDL12 = b'''<?xml version="1.0"?>
<wsdl:definitions xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/"
 xmlns:soap12="http://schemas.xmlsoap.org/wsdl/soap12/"
 xmlns:tns="urn:intermec:dcws12" targetNamespace="urn:intermec:dcws12">
 <wsdl:message name="PingRequest"><wsdl:part name="p" element="tns:Ping"/></wsdl:message>
 <wsdl:portType name="P"><wsdl:operation name="Ping"><wsdl:input message="tns:PingRequest"/></wsdl:operation></wsdl:portType>
 <wsdl:binding name="B" type="tns:P"><soap12:binding transport="http://schemas.xmlsoap.org/soap/http"/>
  <wsdl:operation name="Ping"><soap12:operation soapAction="urn:Ping"/></wsdl:operation>
 </wsdl:binding>
 <wsdl:service name="S"><wsdl:port name="P" binding="tns:B"><soap12:address location="/soap12"/></wsdl:port></wsdl:service>
</wsdl:definitions>'''

WSDL_NO_ADDRESS = b'''<?xml version="1.0"?>
<wsdl:definitions xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/"
 xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
 xmlns:tns="urn:noaddr" targetNamespace="urn:noaddr">
 <wsdl:message name="PingRequest"><wsdl:part name="p" element="tns:Ping"/></wsdl:message>
 <wsdl:portType name="P"><wsdl:operation name="Ping"><wsdl:input message="tns:PingRequest"/></wsdl:operation></wsdl:portType>
 <wsdl:binding name="B" type="tns:P"><soap:binding transport="http://schemas.xmlsoap.org/soap/http"/>
  <wsdl:operation name="Ping"><soap:operation soapAction="urn:Ping"/></wsdl:operation>
 </wsdl:binding>
</wsdl:definitions>'''


def local_name(tag):
    return tag.rsplit("}", 1)[-1]


class Handler(BaseHTTPRequestHandler):
    requests = []

    def log_message(self, *args):
        pass

    def _send(self, status, body, content_type="text/xml"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        type(self).requests.append(("GET", self.path, dict(self.headers), b""))
        if self.path == "/DeviceConfiguration.wsdl":
            return self._send(200, WSDL11)
        if self.path == "/soap12.wsdl":
            return self._send(200, WSDL12)
        if self.path == "/noaddress.wsdl":
            return self._send(200, WSDL_NO_ADDRESS)
        if self.path == "/bad.wsdl":
            return self._send(200, b"<bad")
        if self.path == "/notwsdl.wsdl":
            return self._send(200, b"<root/>")
        return self._send(404, b"")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        type(self).requests.append(("POST", self.path, dict(self.headers), body))
        root = ET.fromstring(body)
        op = next(node for node in root.iter() if local_name(node.tag) not in {"Envelope", "Body"})
        name = local_name(op.tag)
        if name == "FaultMe":
            fault = b'''<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault><faultcode>s:Server</faultcode><faultstring>configuration rejected</faultstring></s:Fault></s:Body></s:Envelope>'''
            return self._send(200, fault)
        if name == "BadXML":
            return self._send(200, b"<not-xml")
        env = "http://www.w3.org/2003/05/soap-envelope" if self.path == "/soap12" else "http://schemas.xmlsoap.org/soap/envelope/"
        ns = "urn:intermec:dcws12" if self.path == "/soap12" else "urn:intermec:dcws"
        reply = f'''<s:Envelope xmlns:s="{env}" xmlns:d="{ns}"><s:Body><d:{name}Response><d:ok>true</d:ok><d:value>a</d:value><d:value>b</d:value></d:{name}Response></s:Body></s:Envelope>'''.encode()
        return self._send(200, reply, "application/soap+xml" if self.path == "/soap12" else "text/xml")


@pytest.fixture
def server():
    Handler.requests = []
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_port}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join()


def test_wsdl_discovery_auth_host_safety_and_soap11(server):
    manager = IntermecDCWSManager(server, model="IF2", username="admin", password="secret")
    assert manager.endpoint_path == "/dcws"
    assert manager.soap_version == "1.1"
    assert manager.list_operations() == ("BadXML", "FaultMe", "GetConfig", "SetConfig")
    op = manager.get_operation("SetConfig")
    assert op.action == "urn:SetConfig"
    assert op.input_element == "SetConfig"

    result = manager.call("SetConfig", {"rfid": {"enabled": True}, "antenna": [1, 2]})
    assert result == {"ok": "true", "value": ["a", "b"]}

    wsdl_headers = Handler.requests[0][2]
    expected = "Basic " + base64.b64encode(b"admin:secret").decode()
    assert wsdl_headers.get("Authorization") == expected
    post = Handler.requests[-1]
    assert post[1] == "/dcws"
    post_headers = {key.lower(): value for key, value in post[2].items()}
    assert post_headers.get("soapaction") == '"urn:SetConfig"'
    xml = ET.fromstring(post[3])
    assert any(local_name(node.tag) == "enabled" and node.text == "true" for node in xml.iter())
    assert [node.text for node in xml.iter() if local_name(node.tag) == "antenna"] == ["1", "2"]


def test_soap12_content_type_action(server):
    manager = IntermecDCWSManager(server, model="IF61", wsdl_path="/soap12.wsdl")
    assert manager.soap_version == "1.2"
    assert manager.endpoint_path == "/soap12"
    assert manager.call("Ping")["ok"] == "true"
    headers = Handler.requests[-1][2]
    assert "application/soap+xml" in headers.get("Content-Type", "")
    assert 'action="urn:Ping"' in headers.get("Content-Type", "")


def test_wsdl_and_soap_errors(server):
    with pytest.raises(ReaderManagementError, match="invalid Device Configuration WSDL"):
        IntermecDCWSManager(server, model="IF2", wsdl_path="/bad.wsdl")
    with pytest.raises(ReaderManagementError, match="not a WSDL"):
        IntermecDCWSManager(server, model="IF2", wsdl_path="/notwsdl.wsdl")

    manager = IntermecDCWSManager(server, model="IF2")
    with pytest.raises(ReaderManagementError, match="not advertised"):
        manager.call("NoSuchOperation")
    with pytest.raises(ReaderManagementError, match="configuration rejected"):
        manager.call("FaultMe")
    with pytest.raises(ReaderManagementError, match="invalid SOAP XML"):
        manager.call("BadXML")

    no_endpoint = IntermecDCWSManager(server, model="IF2", wsdl_path="/noaddress.wsdl")
    with pytest.raises(ReaderManagementError, match="did not advertise a SOAP endpoint"):
        no_endpoint.call("Ping")


def test_endpoint_override_and_lazy_wsdl(server):
    manager = IntermecDCWSManager(
        server,
        model="IF1",
        endpoint_path="/manual",
        load_wsdl=False,
    )
    assert manager.wsdl is None
    assert manager.list_operations() == ()
    manager.refresh_wsdl()
    assert manager.endpoint_path == "/manual"


def test_factory_and_model_validation(server):
    manager = create_reader_manager(
        "IF2",
        server,
        api="dcws",
        load_wsdl=False,
    )
    assert isinstance(manager, IntermecDCWSManager)
    assert isinstance(
        create_reader_manager("IF61", server, vendor="honeywell", api="soap", load_wsdl=False),
        IntermecDCWSManager,
    )
    with pytest.raises(ValueError, match="auto/dcws/soap"):
        create_reader_manager("IF2", server, api="rest", load_wsdl=False)
    with pytest.raises(ValueError, match="not a supported"):
        IntermecDCWSManager(server, model="FX9500", load_wsdl=False)
