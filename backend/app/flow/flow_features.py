"""
Directional Flow and Feature Representation for AI-NIDS.
Tracks directional network flows: (src_ip, dst_ip, src_port, dst_port, protocol).
Maintains exact statistical features compatible with the ML pipeline.
"""

from dataclasses import dataclass, field
import math
from typing import Any, Dict, List, NamedTuple, Optional
import numpy as np

class DirectionalFlowKey(NamedTuple):
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int  # 6=TCP, 17=UDP, 1=ICMP, etc.

    def __str__(self) -> str:
        return f"{self.src_ip}:{self.src_port}->{self.dst_ip}:{self.dst_port}(p={self.protocol})"

@dataclass
class DirectionalFlow:
    key: DirectionalFlowKey
    first_seen: float
    last_seen: float
    total_packets: int = 0
    total_bytes: int = 0
    packet_lengths: List[int] = field(default_factory=list)
    packet_timestamps: List[float] = field(default_factory=list)

    # TCP Flag counts
    fin_count: int = 0
    syn_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    ack_count: int = 0
    urg_count: int = 0

    is_terminated: bool = False

    def add_packet(
        self,
        length: int,
        timestamp: float,
        tcp_flags: Optional[str] = None
    ) -> None:
        """Updates directional flow counters and timing statistics."""
        self.last_seen = timestamp
        self.total_packets += 1
        self.total_bytes += length
        self.packet_lengths.append(length)
        self.packet_timestamps.append(timestamp)

        if tcp_flags:
            flags = str(tcp_flags).upper()
            if "F" in flags:
                self.fin_count += 1
                self.is_terminated = True
            if "S" in flags:
                self.syn_count += 1
            if "R" in flags:
                self.rst_count += 1
                self.is_terminated = True
            if "P" in flags:
                self.psh_count += 1
            if "A" in flags:
                self.ack_count += 1
            if "U" in flags:
                self.urg_count += 1

    def to_features(self) -> Dict[str, Any]:
        """
        Extracts directional statistical features matching the CIC-IDS2017 schema.
        Duration and IAT are in microseconds to strictly conform to standard NetFlow benchmarks.
        """
        duration_sec = max(0.0, self.last_seen - self.first_seen)
        duration_usec = duration_sec * 1_000_000.0

        lengths = np.array(self.packet_lengths) if self.packet_lengths else np.array([0])
        pkt_len_min = float(np.min(lengths))
        pkt_len_max = float(np.max(lengths))
        pkt_len_mean = float(np.mean(lengths))
        pkt_len_std = float(np.std(lengths))
        pkt_len_var = float(np.var(lengths))

        effective_duration = max(duration_sec, 0.0001)
        flow_bytes_per_sec = float(self.total_bytes / effective_duration)
        flow_packets_per_sec = float(self.total_packets / effective_duration)

        # Inter-arrival times (microseconds)
        if len(self.packet_timestamps) > 1:
            diffs = np.diff(self.packet_timestamps) * 1_000_000.0
            # Clip negative jitter if packet timestamps arrived out of sequence
            diffs = np.clip(diffs, 0.0, None)
            iat_mean = float(np.mean(diffs))
            iat_std = float(np.std(diffs))
            iat_max = float(np.max(diffs))
            iat_min = float(np.min(diffs))
        else:
            iat_mean = 0.0
            iat_std = 0.0
            iat_max = 0.0
            iat_min = 0.0

        return {
            "destination_port": int(self.key.dst_port),
            "flow_duration": float(duration_usec),
            "total_packets": int(self.total_packets),
            "total_bytes": int(self.total_bytes),
            "packet_len_min": pkt_len_min,
            "packet_len_max": pkt_len_max,
            "packet_len_mean": pkt_len_mean,
            "packet_len_std": pkt_len_std,
            "packet_len_var": pkt_len_var,
            "flow_bytes_per_sec": flow_bytes_per_sec,
            "flow_packets_per_sec": flow_packets_per_sec,
            "flow_iat_mean": iat_mean,
            "flow_iat_std": iat_std,
            "flow_iat_max": iat_max,
            "flow_iat_min": iat_min,
            "fin_flag_count": int(self.fin_count),
            "syn_flag_count": int(self.syn_count),
            "rst_flag_count": int(self.rst_count),
            "psh_flag_count": int(self.psh_count),
            "ack_flag_count": int(self.ack_count),
            "urg_flag_count": int(self.urg_count),
            "avg_packet_size": pkt_len_mean,
            # Metadata for reporting & alerts (not passed to ML scaler)
            "_metadata": {
                "src_ip": self.key.src_ip,
                "dst_ip": self.key.dst_ip,
                "src_port": self.key.src_port,
                "dst_port": self.key.dst_port,
                "protocol": self.key.protocol,
                "first_seen": self.first_seen,
                "last_seen": self.last_seen,
                "duration_sec": duration_sec
            }
        }
