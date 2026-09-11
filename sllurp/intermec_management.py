"""Honeywell/Intermec Device Configuration Web Services (DCWS).

IF-series readers expose a SOAP/WSDL configuration service over HTTP/HTTPS.
Unlike REST readers, the exact SOAP operations are described by the WSDL served
by the reader firmware.  This adapter loads that WSDL, discovers SOAP actions
and the service endpoint, and provides a small document/literal SOAP client.

The WSDL remains authoritative: callers pass the parameter names documented by
the reader's own schema/command reference rather than sllurp hard-coding a
firmware-specific command catalogue.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping
from urllib.parse import urlparse
from xml.etree import ElementTree as ET

from .reader_management import HTTPReaderManager, ReaderManagementError

WSDL_NS = "http://schemas.xmlsoap.org/wsdl/"
SOAP11_BINDING_NS = "http://schemas.xmlsoap.org/wsdl/soap/"
SOAP12_BINDING_NS = "http://schemas.xmlsoap.org/wsdl/soap12/"
SOAP11_ENV_NS = "http://schemas.xmlsoap.org/soap/envelope/"
SOAP12_ENV_NS = "http://www.w3.org/2003/05/soap-envelope"

INTERMEC_DCWS_MODELS = frozenset({"IF1", "IF2", "IF61"})


@dataclass(frozen=True)
class SOAPOperation:
    """One operation discovered from the reader's WSDL."""

    name: str
    action: str | None
    input_element: str


def _model_name(model: str) -> str:
    return "".join(character for character in model.upper() if character.isalnum())


def _local_name(value: str) -> str:
    if "}" in value:
        return value.rsplit("}", 1)[-1]
    return value.rsplit(":", 1)[-1]


def _element_value(element: ET.Element) -> Any:
    children = list(element)
    if not children:
        return (element.text or "").strip()
    result: dict[str, Any] = {}
    for child in children:
        key = _local_name(child.tag)
        value = _element_value(child)
        if key in result:
            current = result[key]
            if not isinstance(current, list):
                result[key] = [current]
            result[key].append(value)
        else:
            result[key] = value
    return result


def _append_value(parent: ET.Element, key: str, value: Any, namespace: str) -> None:
    if isinstance(value, (list, tuple)):
        for item in value:
            _append_value(parent, key, item, namespace)
        return
    tag = f"{{{namespace}}}{key}" if namespace else key
    child = ET.SubElement(parent, tag)
    if isinstance(value, Mapping):
        for nested_key, nested_value in value.items():
            _append_value(child, str(nested_key), nested_value, namespace)
    elif value is not None:
        if isinstance(value, bool):
            child.text = "true" if value else "false"
        else:
            child.text = str(value)


class IntermecDCWSManager:
    """WSDL-driven SOAP management client for Honeywell/Intermec IF readers.

    Parameters:
        base_url: Reader HTTP/HTTPS base URL.
        model: IF1, IF2, or IF61.
        wsdl_path: Reader-served Device Configuration WSDL path.  The manuals
            expose a link named ``DeviceConfiguration.wsdl``; deployments can
            override the path if firmware serves it elsewhere.
        endpoint_path: Optional SOAP endpoint override.  If omitted, it is
            discovered from the WSDL's ``soap:address`` while intentionally
            retaining the configured reader host so credentials cannot be
            redirected to a different host by WSDL content.
    """

    def __init__(
        self,
        base_url: str,
        *,
        model: str,
        username: str | None = None,
        password: str | None = None,
        wsdl_path: str = "/DeviceConfiguration.wsdl",
        endpoint_path: str | None = None,
        timeout: float = 5.0,
        verify_tls: bool = True,
        ca_file: str | None = None,
        cert_file: str | None = None,
        key_file: str | None = None,
        load_wsdl: bool = True,
    ) -> None:
        self.model = _model_name(model)
        if self.model not in INTERMEC_DCWS_MODELS:
            raise ValueError(f"{model!r} is not a supported Intermec DCWS model")
        self.transport = HTTPReaderManager(
            base_url,
            username=username,
            password=password,
            timeout=timeout,
            verify_tls=verify_tls,
            ca_file=ca_file,
            cert_file=cert_file,
            key_file=key_file,
        )
        self.wsdl_path = wsdl_path
        self.endpoint_path = endpoint_path
        self.target_namespace = ""
        self.soap_version = "1.1"
        self.operations: dict[str, SOAPOperation] = {}
        self._wsdl: bytes | None = None
        if load_wsdl:
            self.refresh_wsdl()

    @property
    def wsdl(self) -> bytes | None:
        """Raw reader WSDL from the most recent load."""
        return self._wsdl

    def refresh_wsdl(self) -> dict[str, SOAPOperation]:
        """Reload and parse the reader's Device Configuration WSDL."""
        response = self.transport.request("GET", self.wsdl_path)
        try:
            root = ET.fromstring(response.body)
        except ET.ParseError as exc:
            raise ReaderManagementError(
                "reader returned invalid Device Configuration WSDL",
                body=response.body,
            ) from exc

        if _local_name(root.tag) != "definitions":
            raise ReaderManagementError(
                "Device Configuration document is not a WSDL definitions document",
                body=response.body,
            )

        self._wsdl = response.body
        self.target_namespace = root.attrib.get("targetNamespace", "")

        messages: dict[str, str] = {}
        for message in root.findall(f"{{{WSDL_NS}}}message"):
            name = message.attrib.get("name")
            part = message.find(f"{{{WSDL_NS}}}part")
            if not name or part is None:
                continue
            element_name = part.attrib.get("element") or part.attrib.get("name")
            if element_name:
                messages[name] = _local_name(element_name)

        port_type_inputs: dict[str, str] = {}
        for port_type in root.findall(f"{{{WSDL_NS}}}portType"):
            for operation in port_type.findall(f"{{{WSDL_NS}}}operation"):
                name = operation.attrib.get("name")
                input_node = operation.find(f"{{{WSDL_NS}}}input")
                if not name or input_node is None:
                    continue
                message_name = input_node.attrib.get("message")
                if message_name:
                    local_message = _local_name(message_name)
                    port_type_inputs[name] = messages.get(local_message, name)

        selected_binding: ET.Element | None = None
        selected_address: ET.Element | None = None
        selected_version = "1.1"
        selected_binding_name: str | None = None

        for service in root.findall(f"{{{WSDL_NS}}}service"):
            for port in service.findall(f"{{{WSDL_NS}}}port"):
                address = port.find(f"{{{SOAP11_BINDING_NS}}}address")
                version = "1.1"
                if address is None:
                    address = port.find(f"{{{SOAP12_BINDING_NS}}}address")
                    version = "1.2"
                if address is None:
                    continue
                selected_address = address
                selected_version = version
                selected_binding_name = _local_name(port.attrib.get("binding", ""))
                break
            if selected_address is not None:
                break

        if selected_binding_name:
            for binding in root.findall(f"{{{WSDL_NS}}}binding"):
                if binding.attrib.get("name") == selected_binding_name:
                    selected_binding = binding
                    break

        if selected_binding is None:
            # Some simple WSDLs omit a service/port.  Still expose operation
            # discovery, but require an endpoint override before invoking.
            bindings = root.findall(f"{{{WSDL_NS}}}binding")
            selected_binding = bindings[0] if bindings else None
            if selected_binding is not None:
                if selected_binding.find(f"{{{SOAP12_BINDING_NS}}}binding") is not None:
                    selected_version = "1.2"

        if selected_address is not None and self.endpoint_path is None:
            location = selected_address.attrib.get("location", "")
            parsed = urlparse(location)
            if parsed.scheme and parsed.netloc:
                path = parsed.path or "/"
                if parsed.query:
                    path += "?" + parsed.query
                self.endpoint_path = path
            elif location:
                self.endpoint_path = location

        self.soap_version = selected_version
        operations: dict[str, SOAPOperation] = {}
        if selected_binding is not None:
            soap_ns = (
                SOAP12_BINDING_NS if selected_version == "1.2" else SOAP11_BINDING_NS
            )
            for operation in selected_binding.findall(f"{{{WSDL_NS}}}operation"):
                name = operation.attrib.get("name")
                if not name:
                    continue
                soap_operation = operation.find(f"{{{soap_ns}}}operation")
                action = (
                    soap_operation.attrib.get("soapAction")
                    if soap_operation is not None
                    else None
                )
                operations[name] = SOAPOperation(
                    name=name,
                    action=action,
                    input_element=port_type_inputs.get(name, name),
                )
        self.operations = operations
        return dict(self.operations)

    def list_operations(self) -> tuple[str, ...]:
        """Return operation names advertised by the reader's WSDL."""
        return tuple(sorted(self.operations))

    def get_operation(self, name: str) -> SOAPOperation:
        try:
            return self.operations[name]
        except KeyError as exc:
            available = ", ".join(self.list_operations()) or "none"
            raise ReaderManagementError(
                f"SOAP operation {name!r} is not advertised by reader WSDL; "
                f"available operations: {available}"
            ) from exc

    def _envelope(
        self,
        operation: SOAPOperation,
        parameters: Mapping[str, Any] | None,
    ) -> bytes:
        env_ns = SOAP12_ENV_NS if self.soap_version == "1.2" else SOAP11_ENV_NS
        envelope = ET.Element(f"{{{env_ns}}}Envelope")
        body = ET.SubElement(envelope, f"{{{env_ns}}}Body")
        namespace = self.target_namespace
        operation_tag = (
            f"{{{namespace}}}{operation.input_element}"
            if namespace
            else operation.input_element
        )
        operation_element = ET.SubElement(body, operation_tag)
        for key, value in (parameters or {}).items():
            _append_value(operation_element, str(key), value, namespace)
        return ET.tostring(envelope, encoding="utf-8", xml_declaration=True)

    def call_raw(
        self,
        name: str,
        parameters: Mapping[str, Any] | None = None,
    ) -> ET.Element:
        """Invoke one WSDL-advertised operation and return its SOAP Body element."""
        operation = self.get_operation(name)
        if not self.endpoint_path:
            raise ReaderManagementError(
                "reader WSDL did not advertise a SOAP endpoint; pass endpoint_path"
            )
        payload = self._envelope(operation, parameters)
        headers: dict[str, str]
        if self.soap_version == "1.2":
            content_type = "application/soap+xml; charset=utf-8"
            if operation.action:
                content_type += f'; action="{operation.action}"'
            headers = {"Content-Type": content_type, "Accept": "application/soap+xml"}
        else:
            headers = {"Content-Type": "text/xml; charset=utf-8", "Accept": "text/xml"}
            if operation.action is not None:
                headers["SOAPAction"] = f'"{operation.action}"'

        response = self.transport.request(
            "POST",
            self.endpoint_path,
            data=payload,
            headers=headers,
        )
        try:
            root = ET.fromstring(response.body)
        except ET.ParseError as exc:
            raise ReaderManagementError(
                f"reader returned invalid SOAP XML for {name}",
                body=response.body,
            ) from exc

        body = next((node for node in root.iter() if _local_name(node.tag) == "Body"), None)
        if body is None:
            raise ReaderManagementError(
                f"SOAP response for {name} has no Body",
                body=response.body,
            )
        fault = next((node for node in body if _local_name(node.tag) == "Fault"), None)
        if fault is not None:
            detail = None
            for node in fault.iter():
                if _local_name(node.tag) in {"faultstring", "Text", "Reason"}:
                    value = (node.text or "").strip()
                    if value:
                        detail = value
                        break
            suffix = f": {detail}" if detail else ""
            raise ReaderManagementError(
                f"SOAP operation {name} failed{suffix}",
                body=response.body,
            )
        return body

    def call(
        self,
        name: str,
        parameters: Mapping[str, Any] | None = None,
    ) -> Any:
        """Invoke an operation and convert its SOAP Body payload to Python values."""
        body = self.call_raw(name, parameters)
        payload = list(body)
        if not payload:
            return None
        if len(payload) == 1:
            return _element_value(payload[0])
        return {_local_name(node.tag): _element_value(node) for node in payload}
