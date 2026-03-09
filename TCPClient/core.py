import atexit
import json
import os
import re
import socket
import sqlite3
import sys
import threading
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

try:
    import serial
except Exception:
    serial = None

# TCP server (sink connects here)
TCP_BIND_HOST = os.getenv("WWSN_TCP_BIND", "0.0.0.0")
TCP_PORT = int(os.getenv("WWSN_TCP_PORT", "60000"))
TIMEOUT = 1000
DEBUG_TCP_HEX = os.getenv("WWSN_DEBUG_TCP_HEX", "1") == "1"
DEBUG_TCP_HEX_MAX = int(os.getenv("WWSN_DEBUG_TCP_HEX_MAX", "256"))
DEBUG_PACKET_ANALYSIS = os.getenv("WWSN_DEBUG_PACKET_ANALYSIS", "1") == "1"
RUN_TS = datetime.now().strftime("%Y%m%d_%H%M%S")
RUNTIME_LOG_FILE = os.getenv("WWSN_RUNTIME_LOG_FILE", f"server_runtime_{RUN_TS}.log")

_ORIGINAL_STDOUT = sys.stdout
_runtime_log_fp = None
_console_lock = threading.Lock()

PROTO_ROUTE_REQUEST = 0x01
PROTO_ROUTE_REPLY = 0x02
PROTO_DATA_PACKET = 0x03
PROTO_ACK_PACKET = 0x04
PROTO_JOIN_REQUEST = 0x10
PROTO_JOIN_ASSIGN = 0x11
PROTO_CONTROL_PACKET = 0x20
PROTO_CONTROL_ACK = 0x21
PROTO_STATUS_PACKET = 0x22


def console_print(msg):
    with _console_lock:
        _ORIGINAL_STDOUT.write(f"{msg}\n")
        _ORIGINAL_STDOUT.flush()


def enable_runtime_file_logging():
    global _runtime_log_fp
    if _runtime_log_fp is not None:
        return os.path.abspath(_runtime_log_fp.name)
    log_path = os.path.abspath(RUNTIME_LOG_FILE)
    _runtime_log_fp = open(log_path, "a", encoding="utf-8", buffering=1)
    sys.stdout = _runtime_log_fp
    sys.stderr = _runtime_log_fp
    return log_path


def close_runtime_file_logging():
    global _runtime_log_fp
    if _runtime_log_fp is None:
        return
    try:
        _runtime_log_fp.flush()
    except Exception:
        pass
    try:
        _runtime_log_fp.close()
    except Exception:
        pass
    _runtime_log_fp = None


def detect_primary_ipv4():
    try:
        # Probe routing table to get the outbound LAN IPv4.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        pass
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception:
        return "127.0.0.1"


def hex_preview(data: bytes, max_bytes: int):
    if not data:
        return ""
    shown = data[:max_bytes]
    hex_str = " ".join(f"{b:02X}" for b in shown)
    if len(data) > max_bytes:
        hex_str += f" ... (+{len(data) - max_bytes}B)"
    return hex_str


def protocol_name(proto: int):
    names = {
        PROTO_ROUTE_REQUEST: "ROUTE_REQUEST",
        PROTO_ROUTE_REPLY: "ROUTE_REPLY",
        PROTO_DATA_PACKET: "DATA_PACKET",
        PROTO_ACK_PACKET: "ACK_PACKET",
        PROTO_JOIN_REQUEST: "JOIN_REQUEST",
        PROTO_JOIN_ASSIGN: "JOIN_ASSIGN",
        PROTO_CONTROL_PACKET: "CONTROL_PACKET",
        PROTO_CONTROL_ACK: "CONTROL_ACK",
        PROTO_STATUS_PACKET: "STATUS_PACKET",
    }
    return names.get(proto, f"UNKNOWN_{proto}")


def to_int(value, default=0):
    try:
        return int(value)
    except Exception:
        return default


def decode_ascii_payload(payload_bytes):
    chars = []
    for b in payload_bytes:
        if b in (0x00, 0xFF):
            continue
        chars.append(chr(b) if 32 <= b <= 126 else ".")
    return "".join(chars).strip()


def parse_hex_packet_line(hex_line):
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", hex_line)
    if len(cleaned) < 16 or len(cleaned) % 2 != 0:
        return None
    try:
        data_bytes = [int(cleaned[i : i + 2], 16) for i in range(0, len(cleaned), 2)]
    except Exception:
        return None
    if len(data_bytes) < 8:
        return None
    return {
        "bytes": data_bytes,
        "sourceMacH": data_bytes[0],
        "sourceMacL": data_bytes[1],
        "sourceID": data_bytes[2],
        "forwardID": data_bytes[3],
        "forwardtoID": data_bytes[4],
        "destID": data_bytes[5],
        "protocol": data_bytes[6],
        "packetID": data_bytes[7],
        "payload": data_bytes[8:],
    }


def analyze_hex_packet(packet, rssi, noise, ts_str):
    proto = packet["protocol"]
    proto_text = protocol_name(proto)
    rssi_i = to_int(rssi, -99)
    noise_i = to_int(noise, -99)
    print(
        f"[{ts_str}] HEX ANALYSIS proto={proto_text}({proto}) "
        f"src={packet['sourceID']} fwd={packet['forwardID']} "
        f"to={packet['forwardtoID']} dst={packet['destID']} "
        f"pkt={packet['packetID']} len={len(packet['bytes'])} "
        f"RSSI={rssi_i}dBm NOISE={noise_i}dBm"
    )

    payload = packet["payload"]
    payload_ascii = decode_ascii_payload(payload)

    if proto == PROTO_DATA_PACKET and len(payload) >= 4:
        temp = payload[0] + payload[1] / 100.0
        hum = payload[2] + payload[3] / 100.0
        print(f"[{ts_str}] DATA DECODE temp={temp:.2f}C hum={hum:.2f}%")
        return

    if proto == PROTO_JOIN_REQUEST:
        uid = payload_ascii[:8] if payload_ascii else ""
        print(f"[{ts_str}] JOIN_REQ DECODE uid={uid or 'N/A'}")
        return

    if proto == PROTO_JOIN_ASSIGN:
        uid = payload_ascii[:8] if payload_ascii else ""
        assigned = payload_ascii[8:10] if len(payload_ascii) >= 10 else ""
        print(f"[{ts_str}] JOIN_ASSIGN DECODE uid={uid or 'N/A'} assigned={assigned or 'N/A'}")
        return

    if proto in (PROTO_CONTROL_PACKET, PROTO_CONTROL_ACK, PROTO_STATUS_PACKET):
        if payload_ascii:
            print(f"[{ts_str}] CTRL/STAT PAYLOAD {payload_ascii}")
        else:
            print(f"[{ts_str}] CTRL/STAT PAYLOAD <empty>")
        return

    if payload_ascii:
        print(f"[{ts_str}] PAYLOAD ASCII {payload_ascii}")


def set_exclusive_port(sock):
    if os.name == "nt" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    elif hasattr(socket, "SO_REUSEADDR"):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

# Web UI server
WEB_HOST = os.getenv("WWSN_WEB_HOST", "0.0.0.0")
WEB_PORT = int(os.getenv("WWSN_WEB_PORT", "8080"))

# Data file
DB_FILE = os.getenv("WWSN_DB_FILE", "Data20250527.db")

# Serial fallback (optional)
SERIAL_PORT = os.getenv("WWSN_SERIAL_PORT", "")
SERIAL_BAUD = int(os.getenv("WWSN_SERIAL_BAUD", "115200"))
SERIAL_TIMEOUT = float(os.getenv("WWSN_SERIAL_TIMEOUT", "0.2"))

# Command retry/timeout
CMD_ACK_TIMEOUT = float(os.getenv("WWSN_ACK_TIMEOUT", "3.0"))
CMD_RETRY_MAX = int(os.getenv("WWSN_ACK_RETRY_MAX", "3"))

# Node online timeout
NODE_OFFLINE_TIMEOUT = float(os.getenv("WWSN_NODE_OFFLINE_TIMEOUT", "120"))

# Optional plot (disabled by default)
ENABLE_PLOT = False

# Throughput stats
throughput_data = []
time_stamps = []
lock = threading.Lock()

# Runtime state for web UI
state_lock = threading.Lock()
state = {
    "connected": False,
    "addr": "",
    "link": "none",
    "serial": {"port": "", "open": False},
    "last_throughput": 0.0,
    "last_packets": {},
    "recent_acks": [],
    "cmd_log": [],
    "topology": {"nodes": {}, "edges": {}},
    "node_status": {},
}

conn_lock = threading.Lock()
active_conn = None
active_addr = None
seq_counter = 0
serial_lock = threading.Lock()
serial_conn = None
pending_lock = threading.Lock()
pending_cmds = {}


def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute(
        """CREATE TABLE IF NOT EXISTS DataPacket (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            throughput REAL,
            sourceMacH INTEGER,
            sourceMacL INTEGER,
            sourceID INTEGER,
            forwardID INTEGER,
            forwardtoID INTEGER,
            destID INTEGER,
            protocol INTEGER,
            packetID INTEGER,
            temperature REAL,
            humidity REAL,
            isMalicious INTEGER DEFAULT 0,
            maliciousType INTEGER DEFAULT 0
        )"""
    )

    cursor.execute(
        """CREATE TABLE IF NOT EXISTS SnifferTable (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            data_packet_id INTEGER,
            lastSniffTime INTEGER,
            sourceID INTEGER,
            snifferID INTEGER,
            forwardCount INTEGER,
            sourceCount INTEGER,
            ackCount INTEGER,
            routeReqCount INTEGER,
            routeRepCount INTEGER,
            lastRSSI INTEGER,
            FOREIGN KEY (data_packet_id) REFERENCES DataPacket (id)
        )"""
    )

    cursor.execute(
        """CREATE TABLE IF NOT EXISTS PathInfo (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            data_packet_id INTEGER,
            node_id INTEGER,
            rssi INTEGER,
            noise INTEGER,
            FOREIGN KEY (data_packet_id) REFERENCES DataPacket (id)
        )"""
    )

    cursor.execute("PRAGMA table_info(DataPacket)")
    data_packet_cols = {row[1] for row in cursor.fetchall()}
    if "isMalicious" not in data_packet_cols:
        cursor.execute("ALTER TABLE DataPacket ADD COLUMN isMalicious INTEGER DEFAULT 0")
    if "maliciousType" not in data_packet_cols:
        cursor.execute("ALTER TABLE DataPacket ADD COLUMN maliciousType INTEGER DEFAULT 0")

    conn.commit()
    conn.close()


def update_last_packet(data_packet, ts, throughput):
    with state_lock:
        state["last_packets"][data_packet["sourceID"]] = {
            "sourceID": data_packet["sourceID"],
            "temperature": data_packet["temperature"],
            "humidity": data_packet["humidity"],
            "timestamp": datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
            "ts": ts,
            "throughput": throughput,
        }
    touch_node(data_packet["sourceID"])


def update_topology(source_id, dest_id, data_bytes, ts):
    node_data_bytes = data_bytes[36:]
    path_nodes = []
    for i in range(0, len(node_data_bytes), 3):
        if i + 2 >= len(node_data_bytes):
            break
        node_id = node_data_bytes[i]
        if node_id == 0:
            break
        path_nodes.append(node_id)

    seq = [source_id] + path_nodes + [dest_id]
    edges = []
    for i in range(len(seq) - 1):
        a = seq[i]
        b = seq[i + 1]
        if a == 0 or b == 0:
            continue
        edges.append((a, b))

    with state_lock:
        nodes = state["topology"]["nodes"]
        ed = state["topology"]["edges"]
        for node in seq:
            if node == 0:
                continue
            nodes[node] = ts
        for a, b in edges:
            key = f"{a}-{b}"
            ed[key] = {"a": a, "b": b, "last": ts}
    for node in seq:
        if node:
            touch_node(node)


def add_ack(node_id, cmd, seq, status):
    with state_lock:
        state["recent_acks"].append(
            {
                "node": node_id,
                "cmd": cmd,
                "seq": seq,
                "status": status,
                "time": datetime.now().strftime("%H:%M:%S"),
            }
        )
        if len(state["recent_acks"]) > 50:
            state["recent_acks"] = state["recent_acks"][-50:]


def add_cmd_log(dest, cmd, p1, p2, seq, status="pending", retries=0):
    with state_lock:
        state["cmd_log"].append(
            {
                "dest": dest,
                "cmd": cmd,
                "p1": p1,
                "p2": p2,
                "seq": seq,
                "time": datetime.now().strftime("%H:%M:%S"),
                "status": status,
                "retries": retries,
            }
        )
        if len(state["cmd_log"]) > 50:
            state["cmd_log"] = state["cmd_log"][-50:]


def update_cmd_log_status(seq, status, retries=None):
    with state_lock:
        for entry in reversed(state["cmd_log"]):
            if entry.get("seq") == seq:
                entry["status"] = status
                if retries is not None:
                    entry["retries"] = retries
                break


def touch_node(node_id, extra=None):
    now = time.time()
    with state_lock:
        info = state["node_status"].get(node_id, {})
        info["id"] = node_id
        info["last_seen"] = now
        if extra:
            info.update(extra)
        state["node_status"][node_id] = info


def save_data_to_db(packet_data, RSSI, envirRSSI, ts, throughput):
    packet_data = re.sub(r"[^0-9A-Fa-f]", "", packet_data)
    try:
        processed_data = []
        data_bytes = [int(packet_data[i : i + 2], 16) for i in range(0, len(packet_data), 2)]
        for i in range(len(data_bytes)):
            if i >= 8 and data_bytes[i] == 0xFF:
                processed_data.append(0x00)
            else:
                processed_data.append(data_bytes[i])
        data_bytes = processed_data
    except ValueError as e:
        print(f"parse error: {e}")
        return

    if len(data_bytes) < 12:
        print(f"packet too short: {data_bytes}")
        return

    temperature = data_bytes[8] + data_bytes[9] / 100.0
    humidity = data_bytes[10] + data_bytes[11] / 100.0

    data_packet = {
        "sourceMacH": data_bytes[0],
        "sourceMacL": data_bytes[1],
        "sourceID": data_bytes[2],
        "forwardID": data_bytes[3],
        "forwardtoID": data_bytes[4],
        "destID": data_bytes[5],
        "protocol": data_bytes[6],
        "packetID": (data_bytes[2] << 8) | data_bytes[7],
        "temperature": temperature,
        "humidity": humidity,
    }

    node_is_malicious = 0
    node_malicious_type = 0
    with state_lock:
        info = state["node_status"].get(data_packet["sourceID"], {})
        node_is_malicious = to_int(info.get("isMalicious", 0), 0)
        node_malicious_type = to_int(info.get("maliciousType", 0), 0)

    if data_packet["protocol"] == PROTO_STATUS_PACKET:
        payload_ascii = decode_ascii_payload(data_bytes[8:])
        parts = [p.strip() for p in payload_ascii.split(",") if p.strip()]
        # Payload format: S,nodeID,roundTime,onoffEnabled,onoffOn,isMalicious,maliciousType,dropPolicy,dropRate
        if len(parts) >= 7 and parts[0] == "S":
            node_is_malicious = to_int(parts[5], node_is_malicious)
            node_malicious_type = to_int(parts[6], node_malicious_type)

    if node_is_malicious == 0:
        node_malicious_type = 0

    data_packet["isMalicious"] = node_is_malicious
    data_packet["maliciousType"] = node_malicious_type

    if DEBUG_PACKET_ANALYSIS:
        ts_str = datetime.fromtimestamp(ts).strftime("%H:%M:%S")
        rssi_i = to_int(RSSI, -99)
        noise_i = to_int(envirRSSI, -99)
        print(
            f"[{ts_str}] PACKET ANALYSIS "
            f"proto={protocol_name(data_packet['protocol'])}({data_packet['protocol']}) "
            f"src={data_packet['sourceID']} fwd={data_packet['forwardID']} "
            f"to={data_packet['forwardtoID']} dst={data_packet['destID']} "
            f"pkt={data_packet['packetID']} "
            f"T={data_packet['temperature']:.2f}C H={data_packet['humidity']:.2f}% "
            f"MAL={data_packet['isMalicious']}/{data_packet['maliciousType']} "
            f"RSSI={rssi_i}dBm NOISE={noise_i}dBm len={len(data_bytes)}"
        )

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        """INSERT INTO DataPacket (timestamp, throughput, sourceMacH, sourceMacL, sourceID,
        forwardID, forwardtoID, destID, protocol, packetID, temperature, humidity, isMalicious, maliciousType)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            ts,
            throughput,
            data_packet["sourceMacH"],
            data_packet["sourceMacL"],
            data_packet["sourceID"],
            data_packet["forwardID"],
            data_packet["forwardtoID"],
            data_packet["destID"],
            data_packet["protocol"],
            data_packet["packetID"],
            data_packet["temperature"],
            data_packet["humidity"],
            data_packet["isMalicious"],
            data_packet["maliciousType"],
        ),
    )
    data_packet_id = cursor.lastrowid

    sniffer_tables = []
    sniffer_start = 12
    for _ in range(2):
        if len(data_bytes) < sniffer_start + 12:
            break
        lastsnifftime = int.from_bytes(
            data_bytes[sniffer_start : sniffer_start + 4], "big", signed=False
        )
        if lastsnifftime == 0 or data_bytes[sniffer_start + 5] == 0:
            sniffer_start += 12
            continue
        sniffer_data = {
            "lastSniffTime": lastsnifftime,
            "sourceID": data_bytes[sniffer_start + 4],
            "snifferID": data_bytes[sniffer_start + 5],
            "forwardCount": data_bytes[sniffer_start + 6],
            "sourceCount": data_bytes[sniffer_start + 7],
            "ackCount": data_bytes[sniffer_start + 8],
            "routeReqCount": data_bytes[sniffer_start + 9],
            "routeRepCount": data_bytes[sniffer_start + 10],
            "lastRSSI": data_bytes[sniffer_start + 11] - 256,
        }
        sniffer_tables.append(sniffer_data)
        sniffer_start += 12

    for sniffer_table in sniffer_tables:
        if sniffer_table["sourceID"] != 0:
            cursor.execute(
                """INSERT INTO SnifferTable (data_packet_id, lastSniffTime, sourceID,
                snifferID, forwardCount, sourceCount, ackCount, routeReqCount, routeRepCount,
                lastRSSI) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    data_packet_id,
                    sniffer_table["lastSniffTime"],
                    sniffer_table["sourceID"],
                    sniffer_table["snifferID"],
                    sniffer_table["forwardCount"],
                    sniffer_table["sourceCount"],
                    sniffer_table["ackCount"],
                    sniffer_table["routeReqCount"],
                    sniffer_table["routeRepCount"],
                    sniffer_table["lastRSSI"],
                ),
            )

    parse_and_save_path_info(cursor, data_packet_id, data_bytes[36:], data_bytes, RSSI, envirRSSI)
    conn.commit()
    conn.close()

    update_last_packet(data_packet, ts, throughput)
    update_topology(data_packet["sourceID"], data_packet["destID"], data_bytes, ts)


def parse_and_save_path_info(cursor, data_packet_id, node_data_bytes, data_bytes, RSSI, envirRSSI):
    if len(node_data_bytes) < 3:
        print("not enough path data")
        return

    cursor.execute(
        """INSERT INTO PathInfo (data_packet_id, node_id, rssi, noise)
        VALUES (?, ?, ?, ?)""",
        (data_packet_id, data_bytes[2], 0, 0),
    )

    for i in range(0, len(node_data_bytes), 3):
        if i + 2 >= len(node_data_bytes) or node_data_bytes[i] == 0:
            break
        node_id = node_data_bytes[i]
        rssi = node_data_bytes[i + 1] - 256
        noise = node_data_bytes[i + 2] - 256

        cursor.execute(
            """INSERT INTO PathInfo (data_packet_id, node_id, rssi, noise)
            VALUES (?, ?, ?, ?)""",
            (data_packet_id, node_id, rssi, noise),
        )

    cursor.execute(
        """INSERT INTO PathInfo (data_packet_id, node_id, rssi, noise)
        VALUES (?, ?, ?, ?)""",
        (data_packet_id, data_bytes[5], RSSI, envirRSSI),
    )


def filter_data(data):
    line = data.strip()
    if not line:
        return None
    # Accept a plain hex line like: "FF FF 02 02 01 01 03 12 ..."
    if re.fullmatch(r"(?:[0-9A-Fa-f]{2}\s+){11,}[0-9A-Fa-f]{2}", line):
        return line
    # Backward-compatible fallback: extract from mixed text.
    match = re.search(r"(?:[0-9A-Fa-f]{2}\s+){11,}[0-9A-Fa-f]{2}", line)
    if match:
        return match.group(0)
    return None


def getRSSItoCH(data):
    match = re.search(r"receivedPacketWithRSSI: (-?\d+)dBm", data)
    if match:
        return match.group(1)
    return None


def getEnvirRSSItoCH(data):
    match = re.search(r"currentChannelNoise: (-?\d+)dBm", data)
    if match:
        return match.group(1)
    return None


def parse_ack_line(line):
    match = re.search(r"ACK,A,(\d+),([A-Z]+),(\d+),(\d+)", line)
    if not match:
        return None
    seq = int(match.group(1))
    cmd = match.group(2)
    status = int(match.group(3))
    node_id = int(match.group(4))
    return node_id, cmd, seq, status


def parse_status_line(line):
    if not line.startswith("STAT,"):
        return None
    parts = [p.strip() for p in line.strip().split(",") if p.strip()]
    if len(parts) < 9:
        return None
    idx = 1
    if parts[1] == "S":
        idx += 1
    try:
        node_id = int(parts[idx])
        round_time = int(parts[idx + 1])
        onoff_enabled = int(parts[idx + 2])
        onoff_on = int(parts[idx + 3])
        is_malicious = int(parts[idx + 4])
        malicious_type = int(parts[idx + 5])
        drop_policy = int(parts[idx + 6])
        drop_rate = int(parts[idx + 7])
    except Exception:
        return None
    return {
        "id": node_id,
        "roundTime": round_time,
        "onoffEnabled": onoff_enabled,
        "onoffOn": onoff_on,
        "isMalicious": is_malicious,
        "maliciousType": malicious_type,
        "dropPolicy": drop_policy,
        "dropRate": drop_rate,
    }


def handle_ack(node_id, cmd, seq, status):
    add_ack(node_id, cmd, seq, status)
    touch_node(node_id)
    with pending_lock:
        entry = pending_cmds.pop(seq, None)
    if entry is not None:
        update_cmd_log_status(seq, "acked", retries=entry.get("retries", 0))


def set_active_conn(conn, addr):
    global active_conn, active_addr
    with conn_lock:
        active_conn = conn
        active_addr = addr
    with state_lock:
        state["connected"] = True
        state["addr"] = f"{addr[0]}:{addr[1]}"
        state["link"] = "tcp"


def clear_active_conn(conn):
    global active_conn, active_addr
    with conn_lock:
        if active_conn is conn:
            active_conn = None
            active_addr = None
    with state_lock:
        state["connected"] = False
        state["addr"] = ""
        if state["serial"].get("open"):
            state["link"] = "serial"
        else:
            state["link"] = "none"


def make_stream_state():
    return {
        "line_buffer": "",
        "bytes_received": 0,
        "last_time": time.time(),
        "last_rssi": "-99",
        "last_noise": "-99",
    }


def process_incoming_bytes(data, stream_state):
    stream_state["bytes_received"] += len(data)

    current_time = time.time()
    if current_time - stream_state["last_time"] >= 1.0:
        with lock:
            throughput_data.append(stream_state["bytes_received"] / 1024 / 1024)
            time_stamps.append(current_time)
            with state_lock:
                state["last_throughput"] = throughput_data[-1]
        stream_state["bytes_received"] = 0
        stream_state["last_time"] = current_time

    decoded_data = data.decode("utf-8", errors="ignore")
    text = stream_state.get("line_buffer", "") + decoded_data
    normalized = text.replace("\r", "\n")
    parts = normalized.split("\n")
    if normalized.endswith("\n"):
        stream_state["line_buffer"] = ""
    else:
        stream_state["line_buffer"] = parts.pop() if parts else ""

    for raw_line in parts:
        line = raw_line.strip()
        if not line:
            continue
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        rssi = getRSSItoCH(line)
        if rssi is not None:
            stream_state["last_rssi"] = rssi
            if DEBUG_PACKET_ANALYSIS:
                print(f"[{ts}] METRIC RSSI={rssi}dBm")
        noise = getEnvirRSSItoCH(line)
        if noise is not None:
            stream_state["last_noise"] = noise
            if DEBUG_PACKET_ANALYSIS:
                print(f"[{ts}] METRIC NOISE={noise}dBm")

        ack = parse_ack_line(line)
        if ack:
            node_id, cmd, seq, status = ack
            handle_ack(node_id, cmd, seq, status)
            if DEBUG_PACKET_ANALYSIS:
                print(f"[{ts}] ACK ANALYSIS node={node_id} cmd={cmd} seq={seq} status={status}")
            continue
        status = parse_status_line(line)
        if status:
            touch_node(status["id"], status)
            if DEBUG_PACKET_ANALYSIS:
                print(
                    f"[{ts}] STAT ANALYSIS node={status['id']} round={status['roundTime']} "
                    f"onoff={status['onoffEnabled']}/{status['onoffOn']} "
                    f"mal={status['isMalicious']}/{status['maliciousType']} "
                    f"drop={status['dropPolicy']}/{status['dropRate']}"
                )
            continue
        filtered_data = filter_data(line)
        if filtered_data:
            if DEBUG_TCP_HEX:
                print(f"[{ts}] PARSED HEX: {filtered_data}")
            parsed_packet = parse_hex_packet_line(filtered_data)
            if parsed_packet and DEBUG_PACKET_ANALYSIS:
                analyze_hex_packet(
                    parsed_packet,
                    stream_state.get("last_rssi", "-99"),
                    stream_state.get("last_noise", "-99"),
                    ts,
                )
            last_tp = throughput_data[-1] if throughput_data else 0.0
            save_data_to_db(
                filtered_data,
                stream_state.get("last_rssi", "-99"),
                stream_state.get("last_noise", "-99"),
                time.time(),
                last_tp,
            )
            continue

        if DEBUG_PACKET_ANALYSIS:
            if line.startswith(("RX ", "PKT_RX", "MEMBER_RX", "JOIN_", "ACK,", "STAT,")):
                print(f"[{ts}] TEXT PACKET {line}")
            elif line.startswith(("currentChannelNoise:", "currentChannelSNR:", "receivedPacketWithRSSI:")):
                print(f"[{ts}] TEXT METRIC {line}")


def handle_client(conn, addr):
    set_active_conn(conn, addr)
    stream_state = make_stream_state()

    with conn:
        conn.settimeout(TIMEOUT)
        while True:
            try:
                data = conn.recv(1024)
                if not data:
                    break
                if DEBUG_TCP_HEX:
                    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
                    print(f"[{ts}] TCP RX {len(data)}B: {hex_preview(data, DEBUG_TCP_HEX_MAX)}")
                process_incoming_bytes(data, stream_state)
            except socket.timeout:
                print(f"timeout {TIMEOUT}s, connection closed")
                break
            except Exception as e:
                print(f"recv error: {e}")
                break

    clear_active_conn(conn)


def start_server():
    init_db()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        set_exclusive_port(server_socket)
        bind_host = TCP_BIND_HOST
        try:
            server_socket.bind((bind_host, TCP_PORT))
        except OSError as e:
            print(f"bind {TCP_BIND_HOST}:{TCP_PORT} failed: {e}, fallback to 0.0.0.0")
            bind_host = "0.0.0.0"
            server_socket.bind((bind_host, TCP_PORT))
        server_socket.listen()
        print(f"TCP server listening on {bind_host}:{TCP_PORT}")
        hint_ip = bind_host if bind_host != "0.0.0.0" else detect_primary_ipv4()
        print(f'STM32 sink config: WIFI_SERVER_IP=\"{hint_ip}\", WIFI_SERVER_PORT=\"{TCP_PORT}\"')
        while True:
            conn, addr = server_socket.accept()
            print(f"connected: {addr}")
            thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            thread.start()


def start_serial_reader():
    global serial_conn
    if not SERIAL_PORT:
        return
    if serial is None:
        print("pyserial not available, serial reader disabled")
        return
    try:
        ser = serial.Serial(SERIAL_PORT, SERIAL_BAUD, timeout=SERIAL_TIMEOUT)
    except Exception as e:
        print(f"serial open failed: {e}")
        return

    with serial_lock:
        serial_conn = ser
    with state_lock:
        state["serial"] = {"port": SERIAL_PORT, "open": True}
        if not state["connected"]:
            state["link"] = "serial"

    stream_state = make_stream_state()
    while True:
        try:
            data = ser.read(1024)
            if data:
                process_incoming_bytes(data, stream_state)
        except Exception as e:
            print(f"serial read error: {e}")
            break

    with serial_lock:
        serial_conn = None
    with state_lock:
        state["serial"] = {"port": SERIAL_PORT, "open": False}
        if not state["connected"]:
            state["link"] = "none"


def send_line(line):
    with conn_lock:
        conn = active_conn
    if conn is not None:
        try:
            conn.sendall(line.encode("utf-8"))
            return True, None
        except Exception as e:
            return False, str(e)

    with serial_lock:
        ser = serial_conn
    if ser is not None:
        try:
            ser.write(line.encode("utf-8"))
            return True, None
        except Exception as e:
            return False, str(e)

    return False, "no active link"


def retry_worker():
    while True:
        time.sleep(0.2)
        now = time.time()
        resend = []
        failed = []
        with pending_lock:
            for seq, entry in list(pending_cmds.items()):
                if now - entry["sent_at"] < CMD_ACK_TIMEOUT:
                    continue
                if entry["retries"] >= CMD_RETRY_MAX:
                    failed.append(entry)
                    del pending_cmds[seq]
                else:
                    entry["retries"] += 1
                    entry["sent_at"] = now
                    resend.append(entry)
        for entry in resend:
            ok, _ = send_line(entry["line"])
            update_cmd_log_status(entry["seq"], "retrying" if ok else "retry_failed", entry["retries"])
        for entry in failed:
            update_cmd_log_status(entry["seq"], "failed", entry["retries"])


def send_command(dest, cmd, p1, p2):
    global seq_counter
    cmd = str(cmd).upper()
    seq_counter = (seq_counter + 1) % 256
    line = f"CTRL,{dest},{cmd},{p1},{p2},{seq_counter}\n"
    ok, err = send_line(line)
    if not ok:
        return False, err

    add_cmd_log(dest, cmd, p1, p2, seq_counter, status="pending", retries=0)
    with pending_lock:
        pending_cmds[seq_counter] = {
            "seq": seq_counter,
            "dest": dest,
            "cmd": cmd,
            "p1": p1,
            "p2": p2,
            "sent_at": time.time(),
            "retries": 0,
            "line": line,
        }
    return True, seq_counter


def get_status_snapshot():
    with state_lock:
        last_packets = list(state["last_packets"].values())
        last_packets.sort(key=lambda x: float(x.get("ts", 0.0)), reverse=True)
        nodes = [{"id": k, "last_seen": v} for k, v in state["topology"]["nodes"].items()]
        edges = list(state["topology"]["edges"].values())
        now = time.time()
        node_status = []
        ingest_link_alive = state["connected"] or state["serial"].get("open", False)
        for node_id, info in state["node_status"].items():
            last_seen = info.get("last_seen", 0)
            node_status.append(
                {
                    "id": node_id,
                    "last_seen": last_seen,
                    "online": ingest_link_alive and ((now - last_seen) <= NODE_OFFLINE_TIMEOUT),
                    "roundTime": info.get("roundTime"),
                    "onoffEnabled": info.get("onoffEnabled"),
                    "onoffOn": info.get("onoffOn"),
                    "isMalicious": info.get("isMalicious"),
                    "maliciousType": info.get("maliciousType"),
                    "dropPolicy": info.get("dropPolicy"),
                    "dropRate": info.get("dropRate"),
                }
            )
        node_status.sort(key=lambda x: x["id"])
        return {
            "connected": state["connected"],
            "addr": state["addr"],
            "link": state["link"],
            "serial": dict(state["serial"]),
            "last_throughput": state["last_throughput"],
            "last_packets": last_packets,
            "recent_acks": list(reversed(state["recent_acks"])),
            "cmd_log": list(reversed(state["cmd_log"])),
            "node_status": node_status,
            "topology": {"nodes": nodes, "edges": edges},
            "cmd_retry": {"timeout": CMD_ACK_TIMEOUT, "max": CMD_RETRY_MAX},
            "ingest_link_alive": ingest_link_alive,
        }


def format_ts_for_ui(ts_value):
    try:
        ts_f = float(ts_value)
        return datetime.fromtimestamp(ts_f).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ts_value)


def query_history_packets(node_id=None, limit=50):
    safe_limit = max(1, min(int(limit), 500))
    params = []
    sql = (
        "SELECT id, timestamp, sourceID, forwardID, forwardtoID, destID, protocol, packetID, "
        "temperature, humidity, isMalicious, maliciousType "
        "FROM DataPacket"
    )
    if node_id is not None:
        sql += " WHERE sourceID = ?"
        params.append(int(node_id))
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(safe_limit)

    conn = sqlite3.connect(DB_FILE)
    try:
        cursor = conn.cursor()
        cursor.execute(sql, params)
        rows = cursor.fetchall()
    finally:
        conn.close()

    out = []
    for r in rows:
        out.append(
            {
                "id": r[0],
                "timestamp": format_ts_for_ui(r[1]),
                "sourceID": r[2],
                "forwardID": r[3],
                "forwardtoID": r[4],
                "destID": r[5],
                "protocol": r[6],
                "protocolName": protocol_name(to_int(r[6], -1)),
                "packetID": r[7],
                "temperature": r[8],
                "humidity": r[9],
                "isMalicious": r[10],
                "maliciousType": r[11],
            }
        )
    return out


def query_sniffer_packets(sniffer_id=None, source_id=None, limit=100):
    safe_limit = max(1, min(int(limit), 500))
    params = []
    sql = (
        "SELECT s.id, d.timestamp, s.data_packet_id, s.lastSniffTime, s.sourceID, s.snifferID, "
        "s.forwardCount, s.sourceCount, s.ackCount, s.routeReqCount, s.routeRepCount, s.lastRSSI "
        "FROM SnifferTable s "
        "LEFT JOIN DataPacket d ON d.id = s.data_packet_id "
        "WHERE 1=1"
    )
    if sniffer_id is not None:
        sql += " AND s.snifferID = ?"
        params.append(int(sniffer_id))
    if source_id is not None:
        sql += " AND s.sourceID = ?"
        params.append(int(source_id))
    sql += " ORDER BY s.id DESC LIMIT ?"
    params.append(safe_limit)

    conn = sqlite3.connect(DB_FILE)
    try:
        cursor = conn.cursor()
        cursor.execute(sql, params)
        rows = cursor.fetchall()
    finally:
        conn.close()

    out = []
    for r in rows:
        out.append(
            {
                "id": r[0],
                "timestamp": format_ts_for_ui(r[1]),
                "dataPacketID": r[2],
                "lastSniffTime": r[3],
                "sourceID": r[4],
                "snifferID": r[5],
                "forwardCount": r[6],
                "sourceCount": r[7],
                "ackCount": r[8],
                "routeReqCount": r[9],
                "routeRepCount": r[10],
                "lastRSSI": r[11],
                "summary": f"FWD={r[6]} SRC={r[7]} ACK={r[8]} RREQ={r[9]} RREP={r[10]} RSSI={r[11]}dBm",
            }
        )
    return out


from .webui_page import HTML_PAGE


class ControlHandler(BaseHTTPRequestHandler):
    def _send_json(self, obj, status=200):
        data = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/" or parsed.path.startswith("/index"):
            data = HTML_PAGE.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if parsed.path.startswith("/status"):
            self._send_json(get_status_snapshot())
            return
        if parsed.path.startswith("/history"):
            q = parse_qs(parsed.query or "")
            node_v = q.get("node", [""])[0].strip()
            limit_v = q.get("limit", ["50"])[0].strip()
            node_id = None
            if node_v != "":
                try:
                    node_id = int(node_v)
                except Exception:
                    self._send_json({"error": "invalid node"}, status=400)
                    return
            try:
                limit = int(limit_v) if limit_v else 50
            except Exception:
                self._send_json({"error": "invalid limit"}, status=400)
                return
            rows = query_history_packets(node_id=node_id, limit=limit)
            self._send_json({"ok": True, "rows": rows})
            return
        if parsed.path.startswith("/sniffer_history"):
            q = parse_qs(parsed.query or "")
            sniffer_v = q.get("sniffer", [""])[0].strip()
            source_v = q.get("source", [""])[0].strip()
            limit_v = q.get("limit", ["100"])[0].strip()
            sniffer_id = None
            source_id = None
            if sniffer_v != "":
                try:
                    sniffer_id = int(sniffer_v)
                except Exception:
                    self._send_json({"error": "invalid sniffer"}, status=400)
                    return
            if source_v != "":
                try:
                    source_id = int(source_v)
                except Exception:
                    self._send_json({"error": "invalid source"}, status=400)
                    return
            try:
                limit = int(limit_v) if limit_v else 100
            except Exception:
                self._send_json({"error": "invalid limit"}, status=400)
                return
            rows = query_sniffer_packets(sniffer_id=sniffer_id, source_id=source_id, limit=limit)
            self._send_json({"ok": True, "rows": rows})
            return
        self._send_json({"error": "not found"}, status=404)

    def do_POST(self):
        if self.path.startswith("/command"):
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length).decode("utf-8")
            dest = cmd = p1 = p2 = None
            try:
                payload = json.loads(raw)
                dest = int(payload.get("dest", 255))
                cmd = str(payload.get("cmd", ""))
                p1 = int(payload.get("p1", 0))
                p2 = int(payload.get("p2", 0))
            except Exception:
                data = parse_qs(raw)
                dest = int(data.get("dest", ["255"])[0])
                cmd = str(data.get("cmd", [""])[0])
                p1 = int(data.get("p1", ["0"])[0])
                p2 = int(data.get("p2", ["0"])[0])

            ok, res = send_command(dest, cmd, p1, p2)
            if ok:
                self._send_json({"ok": True, "seq": res})
            else:
                self._send_json({"ok": False, "error": res}, status=400)
            return

        self._send_json({"error": "not found"}, status=404)


class ExclusiveThreadingHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = False

    def server_bind(self):
        set_exclusive_port(self.socket)
        super().server_bind()


def start_web_server():
    server = ExclusiveThreadingHTTPServer((WEB_HOST, WEB_PORT), ControlHandler)
    display_host = WEB_HOST if WEB_HOST != "0.0.0.0" else "127.0.0.1"
    print(f"Web UI running on http://{display_host}:{WEB_PORT}")
    server.serve_forever()


if __name__ == "__main__":
    log_path = enable_runtime_file_logging()
    atexit.register(close_runtime_file_logging)

    web_display_host = detect_primary_ipv4() if WEB_HOST == "0.0.0.0" else WEB_HOST
    console_print(f"[WWSN] Runtime log file: {log_path}")
    console_print(f"[WWSN] Web UI: http://{web_display_host}:{WEB_PORT}")
    console_print(f"[WWSN] TCP bind: {TCP_BIND_HOST}:{TCP_PORT}")
    console_print("[WWSN] Detailed packet/debug output is redirected to runtime log.")

    tcp_thread = threading.Thread(target=start_server, daemon=True)
    tcp_thread.start()
    retry_thread = threading.Thread(target=retry_worker, daemon=True)
    retry_thread.start()
    serial_thread = threading.Thread(target=start_serial_reader, daemon=True)
    serial_thread.start()
    start_web_server()
