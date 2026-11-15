"""
PCAP Reader and Processor for AI-NIDS.
Processes offline PCAP files using the exact same Directional FlowManager
and Feature Extraction pipeline as live traffic capture.
"""

import gc
import logging
import os
from pathlib import Path
import time
from typing import Any, Callable, Dict, List, Optional
from scapy.all import PcapReader, Scapy_Exception

from backend.app.flow.flow_features import DirectionalFlow
from backend.app.flow.flow_manager import FlowManager

logger = logging.getLogger(__name__)

def process_pcap_file(
    file_path: Path,
    flow_callback: Optional[Callable[[DirectionalFlow], None]] = None,
    idle_timeout_sec: float = 15.0,
    active_timeout_sec: float = 60.0,
    max_packets: Optional[int] = None
) -> Dict[str, Any]:
    """
    Parses a PCAP file packet-by-packet, extracts directional flows,
    and invokes flow_callback on every completed flow.
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"PCAP file not found: {file_path}")

    file_size_bytes = path.stat().st_size
    if file_size_bytes == 0:
        return {
            "success": True,
            "packets_count": 0,
            "flows_count": 0,
            "file_size_bytes": 0,
            "duration_sec": 0.0,
            "message": "PCAP file is empty (0 bytes)."
        }

    flow_manager = FlowManager(
        idle_timeout_sec=idle_timeout_sec,
        active_timeout_sec=active_timeout_sec
    )

    packet_count = 0
    completed_flows: List[DirectionalFlow] = []
    start_wall_time = time.time()
    first_pkt_time: Optional[float] = None
    last_pkt_time: Optional[float] = None
    reader = None

    try:
        reader = PcapReader(str(path))
        for pkt in reader:
            packet_count += 1
            pkt_time = float(getattr(pkt, "time", time.time()))

            if first_pkt_time is None:
                first_pkt_time = pkt_time
            last_pkt_time = pkt_time

            finished = flow_manager.process_packet(pkt, current_time=pkt_time)
            for f in finished:
                completed_flows.append(f)
                if flow_callback:
                    flow_callback(f)

            if max_packets and packet_count >= max_packets:
                logger.info(f"Reached max packets limit ({max_packets}) for PCAP.")
                break

        # Flush remaining active flows at end of PCAP
        remaining = flow_manager.flush_all()
        for f in remaining:
            completed_flows.append(f)
            if flow_callback:
                flow_callback(f)

    except Scapy_Exception as se:
        logger.error(f"Scapy error while parsing PCAP {file_path}: {se}")
    except Exception as e:
        logger.error(f"Unexpected error parsing PCAP {file_path}: {e}")
        raise
    finally:
        if reader is not None:
            try:
                reader.close()
            except Exception:
                pass
        gc.collect()

    duration_sec = (last_pkt_time - first_pkt_time) if (first_pkt_time and last_pkt_time) else 0.0

    return {
        "success": True,
        "packets_count": packet_count,
        "flows_count": len(completed_flows),
        "file_size_bytes": file_size_bytes,
        "traffic_duration_sec": round(duration_sec, 3),
        "processing_time_sec": round(time.time() - start_wall_time, 3),
        "completed_flows": completed_flows
    }
