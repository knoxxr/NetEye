# NetEye OT Security Monitor

NetEye is a passive OT/ICS network security monitor, in the spirit of Nozomi Guardian and
Claroty CTD. It reads mirrored (SPAN/TAP) traffic or PCAP files and does four things:

- **Industrial protocol DPI.** It parses the function codes and commands of each protocol.
- **Asset identification.** It extracts vendor, model/order number, firmware, serial number, and
  station name from protocol responses, and infers each asset's role (PLC, RTU/IED, EWS, HMI).
- **Communication map.** It records client → server relationships and the operations used on
  each one (reads, writes, control, program changes).
- **Threat alerts.** It raises alerts for PLC Stop/Start, program download/upload, device restart,
  configuration changes, remote control commands, and similar actions. Alerts are deduplicated
  and can be acknowledged.
- **Baseline anomaly detection.** In learning mode it records which assets, communications
  (client → server per protocol), and commands (function codes per communication) are normal. In
  detection mode it alerts on new assets, new communications, and new commands. A deviation that
  turns out to be legitimate can be accepted into the baseline with one click.

Packet payloads are not stored. Assets, communications, and alerts are kept in SQLite
(`data/neteye.db`).

## Supported protocols

| Protocol | Analysis depth |
|---|---|
| Siemens S7comm (TCP 102) | Commands (Read/Write Var, PLC Stop, Download/Upload, PI services such as `_INSE` / `_DELE` / `P_PROGRAM`), order number and firmware from SZL 0x0011, password transmission |
| Siemens S7comm-plus | Version detection; V1/V2 functions (Get/SetMultiVariables, etc.) |
| Modbus/TCP | All function codes, exceptions, Diagnostics (Force Listen Only, etc.), MEI device identification |
| Schneider UMAS (Modbus FC 90) | PLC Start/Stop, program download/upload |
| EtherNet/IP · CIP | ListIdentity and Get Attributes All identity, CIP services (Reset/Start/Stop, Set Attribute), Logix Read/Write Tag, Unconnected Send |
| DNP3 | Application function codes (Operate, Cold/Warm Restart, Stop Application, file transfer, etc.) |
| IEC 60870-5-104 | I/S/U frames, ASDU types and causes of transmission, control/setpoint/Reset Process commands |
| IEC 61850 | GOOSE (gocbRef, stNum/sqNum, simulation flag), Sampled Values, MMS session detection |
| PROFINET | DCP Identify (station name, model, vendor, IP), DCP Set (IP/name change, factory reset), RT cyclic I/O |
| Mitsubishi SLMP/MC (3E binary) | Remote RUN/STOP/RESET, read/write, CPU model (detected by payload content, so any port works) |
| CC-Link IE (Ethertype 0x890F), CC-Link IE Field Basic | Detection |
| OPC UA | Message types, warning when the security policy is None |
| LLDP | System name, description, management IP |
| EtherCAT, POWERLINK, BACnet/IP, Omron FINS, HART-IP, CODESYS, GE SRTP, and others | Detection by Ethertype or port |

DeviceNet and CC-Link (the original fieldbus) run on CAN or RS-485, not Ethernet, so they don't
appear on a switch mirror port. To see them you need a fieldbus tap or gateway, or you can watch
them indirectly through the EtherNet/IP/CIP traffic on the upper layer.

## Running

Python 3.10 or later is required.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000`, then use the **Analyze PCAP** button to upload a pcap or pcapng
file.

### Live passive capture

Connect a dedicated sensor interface to the switch mirror port, then set the environment
variable:

```bash
export NETEYE_INTERFACE=eth1          # Windows: Npcap required, $env:NETEYE_INTERFACE="Ethernet 2"
uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

### Analyzing PCAPs from the command line

```powershell
python -m backend.capture capture.pcap            # print results only
python -m backend.capture capture.pcap data\neteye.db   # also save to the DB
```

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `NETEYE_INTERFACE` | (none) | Live capture interface |
| `NETEYE_DB` | `data/neteye.db` | SQLite path |
| `NETEYE_MAX_PCAP_MB` | 512 | Upload size limit |
| `NETEYE_LEARNING_HOURS` | 0 | Initial learning window for a new database, in hours. 0 means you switch to detection manually from the dashboard |

## Running the baseline

1. A new installation starts in **learning mode**. Let it observe a representative period of normal
   operation (typically one to two weeks, covering maintenance windows and shift changes), or
   upload PCAPs recorded during normal operation.
2. Press **탐지 모드 시작** (start detection) on the dashboard. Every asset, communication, and
   command seen up to that point becomes the baseline.
3. From then on, anything not in the baseline raises a deviation alert:
   - New asset, or new external (Internet) address: medium
   - New communication: high for an industrial protocol, low for generic TCP/UDP
   - New command: high for run-state control, program, configuration, and control commands;
     medium for writes, discovery, and diagnostics; low for reads
4. For a legitimate change, such as newly installed equipment, press **정상 등록** (accept as
   normal) on the alert. Accepting a communication also accepts the commands already seen on it.

Policy alerts (dangerous commands) fire in every mode, including learning. A packet that already
raised a policy alert does not also raise a deviation alert.

API: `GET /api/baseline`, `POST /api/baseline/mode` (`{"mode": "learning"|"detecting", "hours": 24, "reset": false}`),
`POST /api/alerts/{id}/learn`, `POST /api/alerts/{id}/ack`

The dashboard has no authentication. Bind it to localhost, or put an authenticated reverse
proxy in front of it.

## Structure

```
backend/
  decode.py          Ethernet/VLAN/IPv4/TCP/UDP/ARP byte decoder
  dissectors/        Protocol DPI (modbus, iso_tsap(S7/MMS), enip, power(DNP3/104), layer2, misc)
  engine.py          Asset identification, MAC↔IP merging, communication links, alert generation and deduplication
  baseline.py        Learning/detection modes, asset/communication/command baseline
  storage.py         SQLite persistence
  capture.py         Live capture and PCAP import
  main.py            FastAPI (REST + WebSocket)
frontend/            Dashboard
```

## Verification

```powershell
python -m unittest discover -s backend\tests
```

## Known limitations

- There is no TCP reassembly. A PDU split across multiple segments is analyzed from its first
  segment only.
- S7comm-plus V3 (S7-1200/1500 with newer firmware) is encrypted and integrity-protected, so
  only detection and session information are available.
- The baseline only tracks whether something has been seen. Statistical anomalies (polling
  interval, traffic volume, process value ranges) are not detected yet.
- There is no CVE matching yet. That is the next step.
