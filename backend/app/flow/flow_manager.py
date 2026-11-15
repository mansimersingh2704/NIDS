"""
Directional Flow Manager for AI-NIDS.
Maintains active unidirectional flows, tracks packet arrivals,
and flushes completed or timed-out flows to the detection pipeline.
"""

import logging
import time
from typing import Any, Dict, List, Optional, Tuple
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet

from backend.app.flow.flow_features import DirectionalFlow, DirectionalFlowKey

logger = logging.getLogger(__name__)

class FlowManager:
    """
    Directional Flow Tracker.
    Strictly preserves directionality: A->B and B->A are distinct flows.
    """

    def __init__(
        self,
        idle_timeout_sec: float = 15.0,
        active_timeout_sec: float = 60.0
    ) -> None:
        self.idle_timeout_sec = idle_timeout_sec
        self.active_timeout_sec = active_timeout_sec
        self.active_flows: Dict[DirectionalFlowKey, DirectionalFlow] = {}
        self.total_packets_processed: int = 0
        self.total_flows_created: int = 0
        self.total_flows_completed: int = 0

    def parse_packet(self, packet: Packet) -> Optional[Tuple[DirectionalFlowKey, int, float, Optional[str]]]:
        """
        Extracts directional flow key and metadata from a Scapy packet.
        Returns None for malformed, non-IP, or unsupported packets.
        """
        try:
            pkt_time = float(getattr(packet, "time", time.time()))
            pkt_len = int(len(packet))

            src_ip = None
            dst_ip = None
            proto_num = 0
            src_port = 0
            dst_port = 0
            tcp_flags = None

            if IP in packet:
                src_ip = str(packet[IP].src)
                dst_ip = str(packet[IP].dst)
                proto_num = int(packet[IP].proto)
            elif IPv6 in packet:
                src_ip = str(packet[IPv6].src)
                dst_ip = str(packet[IPv6].dst)
                proto_num = int(packet[IPv6].nh)
            else:
                # Non-IP layer (e.g. pure ARP or link layer)
                return None

            if TCP in packet:
                src_port = int(packet[TCP].sport)
                dst_port = int(packet[TCP].dport)
                tcp_flags = str(packet[TCP].flags)
            elif UDP in packet:
                src_port = int(packet[UDP].sport)
                dst_port = int(packet[UDP].dport)
            elif ICMP in packet:
                src_port = 0
                dst_port = int(packet[ICMP].type)
            else:
                src_port = 0
                dst_port = 0

            key = DirectionalFlowKey(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto_num
            )
            return key, pkt_len, pkt_time, tcp_flags

        except Exception as e:
            logger.debug(f"Error parsing packet: {e}")
            return None

    def process_packet(
        self,
        packet: Packet,
        current_time: Optional[float] = None
    ) -> List[DirectionalFlow]:
        """
        Processes a single packet.
        Returns any flows that completed due to TCP termination or timeout.
        """
        self.total_packets_processed += 1
        parsed = self.parse_packet(packet)
        if not parsed:
            return []

        key, pkt_len, pkt_time, tcp_flags = parsed
        now = current_time if current_time is not None else pkt_time

        completed_flows: List[DirectionalFlow] = []

        flow = self.active_flows.get(key)
        if flow is None:
            flow = DirectionalFlow(
                key=key,
                first_seen=pkt_time,
                last_seen=pkt_time
            )
            self.active_flows[key] = flow
            self.total_flows_created += 1

        flow.add_packet(length=pkt_len, timestamp=pkt_time, tcp_flags=tcp_flags)

        # Check for immediate flow termination via TCP FIN or RST
        if flow.is_terminated:
            completed_flows.append(flow)
            del self.active_flows[key]
            self.total_flows_completed += 1

        # Periodically check timeouts every 50 packets to keep overhead low
        if self.total_packets_processed % 50 == 0:
            timed_out = self.check_timeouts(current_time=now)
            completed_flows.extend(timed_out)

        return completed_flows

    def check_timeouts(self, current_time: float) -> List[DirectionalFlow]:
        """Scans active flows and expires any that exceed idle or active timeouts."""
        expired_keys = []
        expired_flows = []

        for key, flow in self.active_flows.items():
            idle_duration = current_time - flow.last_seen
            active_duration = current_time - flow.first_seen

            if idle_duration >= self.idle_timeout_sec or active_duration >= self.active_timeout_sec:
                expired_keys.append(key)
                expired_flows.append(flow)

        for key in expired_keys:
            del self.active_flows[key]
            self.total_flows_completed += 1

        return expired_flows

    def flush_all(self) -> List[DirectionalFlow]:
        """Flushes and returns all currently active flows (e.g. at end of PCAP capture)."""
        flushed = list(self.active_flows.values())
        self.total_flows_completed += len(flushed)
        self.active_flows.clear()
        return flushed
