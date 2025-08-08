#!/usr/bin/env python3
"""
sniffer.py
A command-line packet sniffer using Scapy with:
 - protocol/IP/port filters
 - suspicious payload pattern detection (SQLi, XSS, command injection heuristics)
 - logging (rotating file) and optional JSON export
 - optional pcap saving
Requirements: scapy
Run as root to capture from interfaces.
"""

import argparse
import logging
import json
import re
import signal
import sys
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional, Dict, Any

try:
    from scapy.all import sniff, wrpcap, rdpcap, IP, IPv6, TCP, UDP, Raw, ICMP, Ether
except Exception as e:
    print("Scapy import failed. Install scapy with: pip install scapy")
    raise

# ---------- Configuration ----------
SUSPICIOUS_PATTERNS = {
    "xss": [r"<script\b", r"javascript:", r"onerror\s*=", r"onload\s*="],
    "sqli": [r"(\bUNION\b|\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bDROP\b|\b--\b|;--|/\*.*\*/)", r"(['\"]).*(\sOR\s|\sAND\s).*(['\"])"],
    "cmd_injection": [r"(;|\|\||\&\&)\s*\w+", r"`[^`]+`", r"\$\([^)]+\)"],
    "credentials": [r"password=|passwd=|pwd=|Authorization:\s*Basic", r"login=", r"username="],
}
# severity weights (used to compute simple risk score)
PATTERN_WEIGHTS = {"xss": 3, "sqli": 5, "cmd_injection": 5, "credentials": 6}
# -----------------------------------

# Initialize logger
logger = logging.getLogger("PacketSniffer")
logger.setLevel(logging.INFO)
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
logger.addHandler(console_handler)


def setup_file_logging(log_file: Optional[str]):
    if not log_file:
        return
    handler = RotatingFileHandler(log_file, maxBytes=2_000_000, backupCount=3)
    handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(handler)
    logger.info(f"File logging enabled -> {log_file}")


def compile_pattern_dict():
    compiled = {}
    for k, patterns in SUSPICIOUS_PATTERNS.items():
        compiled[k] = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in patterns]
    return compiled


COMPILED_PATTERNS = compile_pattern_dict()


def extract_basic_info(pkt) -> Dict[str, Any]:
    info = {}
    # Timestamps
    info["timestamp"] = time.time()
    # Ethernet
    if Ether in pkt:
        info["src_mac"] = pkt[Ether].src
        info["dst_mac"] = pkt[Ether].dst
    # IP / IPv6
    if IP in pkt:
        info["version"] = 4
        info["src_ip"] = pkt[IP].src
        info["dst_ip"] = pkt[IP].dst
        info["proto"] = pkt[IP].proto
    elif IPv6 in pkt:
        info["version"] = 6
        info["src_ip"] = pkt[IPv6].src
        info["dst_ip"] = pkt[IPv6].dst
        info["proto"] = pkt[IPv6].nh
    else:
        info["version"] = None

    # Transport
    if TCP in pkt:
        info["l4_proto"] = "TCP"
        info["src_port"] = pkt[TCP].sport
        info["dst_port"] = pkt[TCP].dport
        info["flags"] = pkt[TCP].flags.value if hasattr(pkt[TCP].flags, "value") else str(pkt[TCP].flags)
    elif UDP in pkt:
        info["l4_proto"] = "UDP"
        info["src_port"] = pkt[UDP].sport
        info["dst_port"] = pkt[UDP].dport
    elif ICMP in pkt:
        info["l4_proto"] = "ICMP"
    else:
        info["l4_proto"] = None

    # Raw payload
    payload_bytes = None
    if Raw in pkt:
        payload_bytes = bytes(pkt[Raw].load)
        info["payload_len"] = len(payload_bytes)
        # try to decode as UTF-8 (fallback to latin1) but never crash
        try:
            info["payload"] = payload_bytes.decode("utf-8", errors="replace")
        except Exception:
            try:
                info["payload"] = payload_bytes.decode("latin1", errors="replace")
            except Exception:
                info["payload"] = None
    else:
        info["payload_len"] = 0
        info["payload"] = None

    return info


def detect_suspicious(payload: Optional[str]) -> Dict[str, Any]:
    """
    Look for known suspicious patterns and return matches + score.
    payload: str or None
    """
    result = {"score": 0, "matches": []}
    if not payload:
        return result
    text = payload
    for category, patterns in COMPILED_PATTERNS.items():
        for pat in patterns:
            if pat.search(text):
                result["matches"].append({"category": category, "pattern": pat.pattern})
                result["score"] += PATTERN_WEIGHTS.get(category, 1)
    return result


# global state (for graceful shutdown)
CAPTURED_PACKETS = []  # store scapy Packet objects if saving to pcap desired
STOP_SIGNAL = False


def signal_handler(sig, frame):
    global STOP_SIGNAL
    logger.info("Signal received, stopping capture...")
    STOP_SIGNAL = True


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


def packet_callback_factory(args, json_output_handle=None):
    """
    Returns a callback function to pass to scapy.sniff(prn=...)
    json_output_handle: file-like to append JSON lines for each detected packet (if provided)
    """

    def handle_packet(pkt):
        global CAPTURED_PACKETS
        if STOP_SIGNAL:
            return

        info = extract_basic_info(pkt)

        # Apply simple CLI filters not handled by BPF (if provided)
        # IP filter
        if args.ip:
            ip_match = (info.get("src_ip") == args.ip) or (info.get("dst_ip") == args.ip)
            if not ip_match:
                return
        # port filter
        if args.port:
            if info.get("src_port") != args.port and info.get("dst_port") != args.port:
                return

        # basic protocol filter (tcp/udp/icmp)
        if args.protocol and args.protocol.lower() != "all":
            if args.protocol.lower() == "tcp" and info.get("l4_proto") != "TCP":
                return
            if args.protocol.lower() == "udp" and info.get("l4_proto") != "UDP":
                return
            if args.protocol.lower() == "icmp" and info.get("l4_proto") != "ICMP":
                return

        # Suspicious detection
        susp = {"enabled": args.suspicious, "result": None}
        if args.suspicious:
            susp_result = detect_suspicious(info.get("payload"))
            susp["result"] = susp_result
            if susp_result["score"] >= (args.suspicious_threshold or 5):
                # Mark as suspicious and log at warning level
                logger.warning(
                    f"SUSPICIOUS pkt: {info.get('src_ip')}:{info.get('src_port')} -> "
                    f"{info.get('dst_ip')}:{info.get('dst_port')} score={susp_result['score']}, matches={susp_result['matches']}"
                )

        # Formatting output
        summary = (
            f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(info['timestamp']))} | "
            f"{info.get('l4_proto') or 'L4?'} | {info.get('src_ip')}:{info.get('src_port')} -> "
            f"{info.get('dst_ip')}:{info.get('dst_port')} | payload_len={info.get('payload_len')}"
        )

        if args.verbose:
            logger.info(summary)
            if info.get("payload"):
                # show truncated payload
                truncated = info["payload"][:512]
                logger.info(f"Payload (truncated 512 bytes):\n{truncated}")
        else:
            logger.info(summary)

        # Save to pcap buffer if requested
        if args.save_pcap:
            CAPTURED_PACKETS.append(pkt)

        # Append JSON per-packet if requested
        if json_output_handle:
            out = {
                "summary": summary,
                "src_ip": info.get("src_ip"),
                "dst_ip": info.get("dst_ip"),
                "src_port": info.get("src_port"),
                "dst_port": info.get("dst_port"),
                "protocol": info.get("l4_proto"),
                "payload_len": info.get("payload_len"),
                "suspicious": susp,
                "timestamp": info.get("timestamp"),
            }
            try:
                json_output_handle.write(json.dumps(out) + "\n")
                json_output_handle.flush()
            except Exception:
                logger.exception("Failed to write JSON output for packet")

    return handle_packet


def main():
    parser = argparse.ArgumentParser(description="CLI Packet Sniffer (Scapy). Use responsibly.")
    parser.add_argument("--iface", help="Interface to capture on (e.g., eth0).", default=None)
    parser.add_argument("--count", help="Number of packets to capture (0 for infinite).", type=int, default=0)
    parser.add_argument("--timeout", help="Stop sniffing after timeout seconds.", type=int, default=None)
    parser.add_argument("--protocol", help="Protocol filter: tcp|udp|icmp|all", default="all")
    parser.add_argument("--ip", help="Filter source or destination IP (simple equality).", default=None)
    parser.add_argument("--port", help="Filter source or destination port.", type=int, default=None)
    parser.add_argument("--bpf", help="Optional BPF filter string (applies at capture level).", default=None)
    parser.add_argument("--save-pcap", help="Save captured packets to this pcap file.", default=None)
    parser.add_argument("--read-pcap", help="Read and analyze an existing pcap file instead of live capture.", default=None)
    parser.add_argument("--log-file", help="Enable rotating file logging to this path.", default=None)
    parser.add_argument("--json-out", help="Append per-packet JSON lines to this file path.", default=None)
    parser.add_argument("--suspicious", help="Enable suspicious payload detection heuristics.", action="store_true")
    parser.add_argument("--suspicious-threshold", help="Score threshold to log suspicious packets (default 5).", type=int, default=5)
    parser.add_argument("--verbose", help="Verbose output (show truncated payloads).", action="store_true")
    parser.add_argument("--no-priv-check", help="Skip privilege warning (use with caution).", action="store_true")

    args = parser.parse_args()

    # Setup logging to file if requested
    setup_file_logging(args.log_file)

    # Privilege check - sniffing usually needs root
    if not args.no_priv_check:
        if hasattr(os := __import__("os"), "geteuid"):
            if os.geteuid() != 0 and args.read_pcap is None:
                logger.warning("You are not running as root — live capturing may fail. Run with sudo/root.")
        else:
            # Windows or unknown environment: user may still be able to capture with WinPcap/Npcap
            pass

    # JSON output handle
    json_handle = None
    if args.json_out:
        try:
            json_handle = open(args.json_out, "a", encoding="utf-8")
            logger.info(f"JSON output enabled -> {args.json_out}")
        except Exception as e:
            logger.error(f"Could not open JSON output file: {e}")
            json_handle = None

    # If reading pcap, process file and exit
    if args.read_pcap:
        pcap_path = Path(args.read_pcap)
        if not pcap_path.exists():
            logger.error(f"PCAP file not found: {pcap_path}")
            sys.exit(2)
        logger.info(f"Reading pcap file: {pcap_path}")
        packets = rdpcap(str(pcap_path))
        callback = packet_callback_factory(args, json_output_handle=json_handle)
        for pkt in packets:
            callback(pkt)
        if json_handle:
            json_handle.close()
        logger.info("PCAP analysis completed.")
        return

    # Live capture
    logger.info("Starting live capture...")
    logger.info(f"Interface: {args.iface or 'default'}, BPF: {args.bpf}, count: {args.count or 'infinite'}")
    callback = packet_callback_factory(args, json_output_handle=json_handle)

    try:
        sniff_kwargs = {
            "prn": callback,
            "store": False,  # we store manually if saving to pcap
        }
        if args.iface:
            sniff_kwargs["iface"] = args.iface
        if args.count and args.count > 0:
            sniff_kwargs["count"] = args.count
        if args.timeout:
            sniff_kwargs["timeout"] = args.timeout
        if args.bpf:
            sniff_kwargs["filter"] = args.bpf

        # Run sniff — this blocks until count reached, timeout, or SIGINT
        sniff(**sniff_kwargs)
    except PermissionError:
        logger.error("Permission denied while trying to sniff packets. Try running with sudo/root.")
    except Exception as e:
        logger.exception(f"Error during sniff: {e}")
    finally:
        # Save pcap if requested
        if args.save_pcap and CAPTURED_PACKETS:
            try:
                wrpcap(args.save_pcap, CAPTURED_PACKETS)
                logger.info(f"Saved {len(CAPTURED_PACKETS)} packets to {args.save_pcap}")
            except Exception:
                logger.exception("Failed to write pcap file.")
        if json_handle:
            json_handle.close()
        logger.info("Capture finished.")


if __name__ == "__main__":
    main()
