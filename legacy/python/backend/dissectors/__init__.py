"""Protocol dispatch: picks dissectors by ethertype, well-known port, then payload content."""

from __future__ import annotations

from backend.decode import Frame
from backend.dissectors import enip, iso_tsap, layer2, misc, modbus, power
from backend.dissectors.base import Finding

# Server-side port -> dissector(payload, to_server)
TCP_PORTS = {
    modbus.PORT: modbus.dissect,
    iso_tsap.PORT: iso_tsap.dissect,
    enip.PORT: enip.dissect,
    power.DNP3_PORT: power.dissect_dnp3,
    power.IEC104_PORT: power.dissect_iec104,
    4840: misc.dissect_opcua,
}
UDP_PORTS = {
    enip.PORT: enip.dissect,
    power.DNP3_PORT: power.dissect_dnp3,
    47808: misc.dissect_bacnet,
}
# Content-based detection for protocols that commonly run on configurable ports.
CONTENT_DISSECTORS = (misc.dissect_slmp, misc.dissect_opcua)


def dissect(frame: Frame) -> list[Finding]:
    if not frame.transport:
        handler = layer2.ETHERTYPE_DISSECTORS.get(frame.ethertype)
        return handler(frame.payload) if handler else []

    if frame.transport not in ("TCP", "UDP") or not frame.payload:
        return []

    table = TCP_PORTS if frame.transport == "TCP" else UDP_PORTS
    for port, to_server in ((frame.dst_port, True), (frame.src_port, False)):
        handler = table.get(port)
        if handler:
            return handler(frame.payload, to_server)

    if frame.transport == "UDP" and enip.IO_PORT in (frame.src_port, frame.dst_port):
        return enip.dissect_io(frame.payload)

    for port, to_server in ((frame.dst_port, True), (frame.src_port, False)):
        handler = misc.PORT_SIGNATURES.get((frame.transport, port))
        if handler:
            return handler(frame.payload, to_server)

    # Unknown ports: try content signatures; direction guessed from port numbers.
    to_server = (frame.dst_port or 0) < (frame.src_port or 0)
    for handler in CONTENT_DISSECTORS:
        findings = handler(frame.payload, to_server)
        if findings:
            return findings
    return []
