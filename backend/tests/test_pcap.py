"""
Unit Tests for PCAP Parsing and Error Handling in AI-NIDS.
"""

import gc
import os
from pathlib import Path
import tempfile
import time
import pytest
from backend.app.capture.pcap_reader import process_pcap_file

def _safe_unlink(p: Path):
    gc.collect()
    for _ in range(5):
        try:
            if p.exists():
                p.unlink()
            break
        except PermissionError:
            time.sleep(0.1)

def test_empty_pcap_file():
    """Verifies that an empty (0 byte) PCAP file is handled gracefully without crashing."""
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        tmp_path = Path(tmp.name)

    try:
        res = process_pcap_file(tmp_path)
        assert res["success"] is True
        assert res["packets_count"] == 0
        assert res["flows_count"] == 0
        assert "empty" in res.get("message", "").lower()
    finally:
        _safe_unlink(tmp_path)

def test_missing_pcap_file():
    """Verifies FileNotFoundError on non-existent file."""
    with pytest.raises(FileNotFoundError):
        process_pcap_file(Path("non_existent_capture_file.pcap"))

def test_malformed_pcap_file():
    """Verifies that a corrupted or non-PCAP binary file is handled safely."""
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        tmp.write(b"NOT_A_VALID_PCAP_MAGIC_HEADER_1234567890")
        tmp_path = Path(tmp.name)

    try:
        # Should gracefully return 0 packets rather than unhandled crash
        res = process_pcap_file(tmp_path)
        assert res["packets_count"] == 0
    finally:
        _safe_unlink(tmp_path)

def test_valid_sample_pcap():
    """Parses pre-generated benign sample PCAP and extracts completed directional flows."""
    sample_path = Path("data/sample_pcaps/benign_traffic.pcap")
    if not sample_path.exists():
        pytest.skip("benign_traffic.pcap not found")

    res = process_pcap_file(sample_path)
    assert res["success"] is True
    assert res["packets_count"] > 0
    assert len(res["completed_flows"]) > 0
