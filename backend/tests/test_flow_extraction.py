"""
Unit Tests for Directional Flow Extraction in AI-NIDS.
Verifies that:
- Flow identification is strictly directional: (src_ip, dst_ip, src_port, dst_port, protocol).
- A-to-B and B-to-A are treated as separate, isolated flows.
- Directional statistics (packets, bytes, TCP flags) are maintained independently.
- Flow timeouts (idle and active) cleanly age out old flows.
"""

import time
import pytest
from scapy.layers.inet import IP, TCP, UDP
from backend.app.flow.flow_features import DirectionalFlow, DirectionalFlowKey
from backend.app.flow.flow_manager import FlowManager

def test_directional_flow_key_uniqueness():
    """Confirms forward and reverse flow keys are strictly distinct."""
    forward_key = DirectionalFlowKey("192.168.1.10", "10.0.0.1", 54321, 80, 6)
    reverse_key = DirectionalFlowKey("10.0.0.1", "192.168.1.10", 80, 54321, 6)

    assert forward_key != reverse_key
    assert str(forward_key) != str(reverse_key)

def test_flow_manager_separates_forward_and_reverse_traffic():
    """
    Simulates packets traveling A -> B and B -> A.
    Verifies that FlowManager creates two separate directional flows.
    """
    manager = FlowManager(idle_timeout_sec=10.0, active_timeout_sec=30.0)
    t0 = 1000.0

    # Packet 1: Client -> Server SYN
    pkt1 = IP(src="192.168.1.50", dst="142.250.190.46") / TCP(sport=51234, dport=443, flags="S")
    pkt1.time = t0

    # Packet 2: Server -> Client SYN-ACK
    pkt2 = IP(src="142.250.190.46", dst="192.168.1.50") / TCP(sport=443, dport=51234, flags="SA")
    pkt2.time = t0 + 0.02

    manager.process_packet(pkt1, current_time=t0)
    manager.process_packet(pkt2, current_time=t0 + 0.02)

    # Active flows must contain both directions separately
    assert len(manager.active_flows) == 2

    forward_key = DirectionalFlowKey("192.168.1.50", "142.250.190.46", 51234, 443, 6)
    reverse_key = DirectionalFlowKey("142.250.190.46", "192.168.1.50", 443, 51234, 6)

    assert forward_key in manager.active_flows
    assert reverse_key in manager.active_flows

    forward_flow = manager.active_flows[forward_key]
    reverse_flow = manager.active_flows[reverse_key]

    assert forward_flow.total_packets == 1
    assert forward_flow.syn_count == 1
    assert forward_flow.ack_count == 0

    assert reverse_flow.total_packets == 1
    assert reverse_flow.syn_count == 1
    assert reverse_flow.ack_count == 1

def test_flow_termination_on_tcp_fin():
    """Tests that a TCP FIN packet terminates the directional flow immediately."""
    manager = FlowManager()
    t0 = 1000.0

    # SYN
    p1 = IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=4000, dport=80, flags="S")
    p1.time = t0
    completed1 = manager.process_packet(p1, current_time=t0)
    assert len(completed1) == 0

    # FIN
    p2 = IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=4000, dport=80, flags="FA")
    p2.time = t0 + 0.1
    completed2 = manager.process_packet(p2, current_time=t0 + 0.1)

    assert len(completed2) == 1
    finished_flow = completed2[0]
    assert finished_flow.fin_count == 1
    assert finished_flow.total_packets == 2
    assert len(manager.active_flows) == 0

def test_flow_manager_idle_timeout():
    """Tests that flows exceeding idle_timeout_sec are flushed."""
    manager = FlowManager(idle_timeout_sec=5.0, active_timeout_sec=20.0)
    t0 = 1000.0

    p1 = IP(src="10.0.0.2", dst="10.0.0.1") / UDP(sport=5000, dport=53)
    p1.time = t0
    manager.process_packet(p1, current_time=t0)

    assert len(manager.active_flows) == 1

    # Check timeout after 6 seconds (exceeds 5.0s idle timeout)
    timed_out = manager.check_timeouts(current_time=t0 + 6.0)
    assert len(timed_out) == 1
    assert len(manager.active_flows) == 0
