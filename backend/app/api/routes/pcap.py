"""Offline PCAP Analysis Routes for AI-NIDS."""
from pathlib import Path
import shutil
import uuid
from typing import Any, Dict, List
from fastapi import APIRouter, File, HTTPException, UploadFile, status

from backend.app.capture.pcap_reader import process_pcap_file
from backend.app.core.config import settings
from backend.app.detection.detection_engine import get_detection_engine
from backend.app.schemas.api_schemas import (
    AnalyzePcapRequest,
    FlowItemResponse,
    PcapAnalysisResponse,
)

router = APIRouter(tags=["PCAP Analysis"])

@router.post("/pcap/upload")
async def upload_pcap(file: UploadFile = File(...)):
    """Uploads a PCAP or PCAPNG capture file for offline security inspection."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="Missing filename.")

    allowed_exts = {".pcap", ".pcapng", ".cap"}
    ext = Path(file.filename).suffix.lower()
    if ext not in allowed_exts:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported file format '{ext}'. Allowed extensions: {', '.join(allowed_exts)}"
        )

    safe_filename = f"{uuid.uuid4().hex[:8]}_{Path(file.filename).name}"
    dest_path = settings.PCAP_STORAGE_DIR / safe_filename

    # Read and enforce max size limit
    max_bytes = settings.MAX_PCAP_FILE_SIZE_MB * 1024 * 1024
    content = await file.read()
    if len(content) > max_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds maximum upload size of {settings.MAX_PCAP_FILE_SIZE_MB} MB."
        )

    with open(dest_path, "wb") as f:
        f.write(content)

    return {
        "success": True,
        "filename": safe_filename,
        "original_name": file.filename,
        "size_bytes": len(content),
        "message": "File uploaded successfully and ready for analysis."
    }

@router.post("/pcap/analyze", response_model=PcapAnalysisResponse)
async def analyze_pcap(request: AnalyzePcapRequest):
    """
    Parses PCAP file, extracts directional flows, and runs ML inference pipeline.
    Identifies benign vs malicious traffic, attack signatures, and generates SOC alerts.
    """
    target_path = settings.PCAP_STORAGE_DIR / request.filename
    if not target_path.exists():
        # Check sample PCAPs directory as fallback
        sample_path = settings.SAMPLE_PCAP_DIR / request.filename
        if sample_path.exists():
            target_path = sample_path
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"PCAP file '{request.filename}' not found on server."
            )

    try:
        summary = process_pcap_file(
            file_path=target_path,
            max_packets=request.max_packets
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Failed to read or parse PCAP file: {str(e)}"
        )

    flows = summary.get("completed_flows", [])
    session_id = f"pcap-{request.filename}"

    # Process all directional flows in high-performance batch
    detection_engine = get_detection_engine()
    results = detection_engine.process_flow_batch(flows, session_id=session_id)

    benign_count = sum(1 for r in results if not r["flow"]["is_malicious"])
    malicious_count = sum(1 for r in results if r["flow"]["is_malicious"])

    attacks_detected: Dict[str, int] = {}
    for r in results:
        if r["flow"]["is_malicious"]:
            atk = r["flow"]["threat_category"]
            attacks_detected[atk] = attacks_detected.get(atk, 0) + 1

    alerts_gen = sum(1 for r in results if r.get("alert") is not None)

    flow_items = [FlowItemResponse(**r["flow"]) for r in results]

    return PcapAnalysisResponse(
        success=True,
        filename=request.filename,
        packets_count=summary.get("packets_count", 0),
        flows_count=len(flows),
        benign_count=benign_count,
        malicious_count=malicious_count,
        attacks_detected=attacks_detected,
        processing_time_sec=summary.get("processing_time_sec", 0.0),
        alerts_generated=alerts_gen,
        detections=flow_items
    )

@router.get("/pcap/samples")
async def list_sample_pcaps():
    """Lists pre-packaged sample PCAPs available for instant demonstration."""
    samples = []
    if settings.SAMPLE_PCAP_DIR.exists():
        for file in sorted(settings.SAMPLE_PCAP_DIR.glob("*.pcap")):
            samples.append({
                "filename": file.name,
                "size_bytes": file.stat().st_size,
                "description": _get_sample_description(file.name)
            })
    return {"samples": samples}

def _get_sample_description(filename: str) -> str:
    descriptions = {
        "benign_traffic.pcap": "Legitimate HTTP web requests, server responses, and DNS lookups.",
        "port_scan_attack.pcap": "Nmap-style multi-port scan probing critical service ports.",
        "ddos_attack.pcap": "High-volume distributed HTTP flood targeting web application port 80.",
        "mixed_traffic.pcap": "Realistic production mix of benign user traffic with interleaved attacks."
    }
    return descriptions.get(filename, "Sample network packet capture.")
