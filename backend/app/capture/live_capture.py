"""
Passive Live Packet Capture Engine for AI-NIDS.
Monitors a network interface strictly in passive, read-only mode using Scapy.
Maintains live directional flows and feeds completed flows into the detection engine.
"""

from datetime import datetime, timezone
import logging
import threading
import time
from typing import Any, Callable, Dict, List, Optional
from scapy.all import AsyncSniffer, conf, get_if_list, get_working_if

from backend.app.flow.flow_features import DirectionalFlow
from backend.app.flow.flow_manager import FlowManager

logger = logging.getLogger(__name__)

def list_network_interfaces() -> List[Dict[str, Any]]:
    """Returns available network capture interfaces with descriptive metadata."""
    interfaces = []
    try:
        raw_list = get_if_list()
        default_iface = getattr(conf, "iface", None)
        default_name = str(default_iface) if default_iface else ""

        for iface in raw_list:
            is_default = (iface == default_name)
            is_loopback = "loopback" in iface.lower() or "127.0.0.1" in iface

            interfaces.append({
                "id": iface,
                "name": iface,
                "is_default": is_default,
                "is_loopback": is_loopback,
                "status": "ready"
            })
    except Exception as e:
        logger.error(f"Error enumerating interfaces: {e}")

    return interfaces

class LiveCaptureEngine:
    """
    Manages a live passive packet capture thread.
    Strictly passive: does not send, inject, or alter any packets.
    """

    def __init__(
        self,
        flow_callback: Optional[Callable[[DirectionalFlow], None]] = None,
        idle_timeout_sec: float = 15.0,
        active_timeout_sec: float = 60.0
    ) -> None:
        self.flow_callback = flow_callback
        self.idle_timeout_sec = idle_timeout_sec
        self.active_timeout_sec = active_timeout_sec

        self.flow_manager = FlowManager(
            idle_timeout_sec=idle_timeout_sec,
            active_timeout_sec=active_timeout_sec
        )

        self._sniffer: Optional[AsyncSniffer] = None
        self._is_running: bool = False
        self._current_interface: Optional[str] = None
        self._start_time: Optional[float] = None
        self._lock = threading.Lock()
        self._timeout_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    @property
    def is_running(self) -> bool:
        return self._is_running

    @property
    def interface(self) -> Optional[str]:
        return self._current_interface

    def start(self, interface: Optional[str] = None) -> Dict[str, Any]:
        """Starts passive capture on the specified interface."""
        with self._lock:
            if self._is_running:
                return {
                    "success": False,
                    "message": f"Capture is already active on interface {self._current_interface}."
                }

            target_iface = interface or str(conf.iface)
            self._current_interface = target_iface
            self._stop_event.clear()

            # Reset manager
            self.flow_manager = FlowManager(
                idle_timeout_sec=self.idle_timeout_sec,
                active_timeout_sec=self.active_timeout_sec
            )

            try:
                self._sniffer = AsyncSniffer(
                    iface=target_iface,
                    prn=self._on_packet,
                    store=False
                )
                self._sniffer.start()
                self._is_running = True
                self._start_time = time.time()

                # Start background timeout sweeper
                self._timeout_thread = threading.Thread(
                    target=self._timeout_sweeper,
                    daemon=True,
                    name="NIDS-TimeoutSweeper"
                )
                self._timeout_thread.start()

                logger.info(f"Live passive capture started on interface {target_iface}")
                return {
                    "success": True,
                    "interface": target_iface,
                    "started_at": datetime.now(timezone.utc).isoformat(),
                    "message": f"Passive monitoring active on {target_iface}"
                }

            except PermissionError as pe:
                self._is_running = False
                logger.error(f"Permission denied starting capture on {target_iface}: {pe}")
                return {
                    "success": False,
                    "error": "PERMISSION_DENIED",
                    "message": "Insufficient permissions to open raw capture socket. Run as Administrator or configure Npcap/libpcap capabilities."
                }
            except Exception as e:
                self._is_running = False
                logger.error(f"Failed to start live capture on {target_iface}: {e}")
                return {
                    "success": False,
                    "error": str(type(e).__name__),
                    "message": f"Capture failed: {str(e)}"
                }

    def stop(self) -> Dict[str, Any]:
        """Stops live capture and flushes any active flows."""
        with self._lock:
            if not self._is_running:
                return {"success": False, "message": "Live capture is not currently running."}

            self._stop_event.set()
            if self._sniffer and self._sniffer.running:
                try:
                    self._sniffer.stop()
                except Exception as e:
                    logger.warning(f"Error stopping sniffer: {e}")

            self._is_running = False

            # Flush remaining active flows
            flushed = self.flow_manager.flush_all()
            for flow in flushed:
                if self.flow_callback:
                    self.flow_callback(flow)

            duration = time.time() - self._start_time if self._start_time else 0.0
            stopped_iface = self._current_interface
            self._current_interface = None

            logger.info(f"Live capture stopped on {stopped_iface}. Flushed {len(flushed)} flows.")
            return {
                "success": True,
                "interface": stopped_iface,
                "duration_sec": round(duration, 2),
                "total_packets": self.flow_manager.total_packets_processed,
                "total_flows": self.flow_manager.total_flows_completed,
                "message": "Live capture stopped successfully."
            }

    def get_stats(self) -> Dict[str, Any]:
        """Returns runtime monitoring counters."""
        uptime = (time.time() - self._start_time) if (self._is_running and self._start_time) else 0.0
        return {
            "is_running": self._is_running,
            "interface": self._current_interface,
            "uptime_seconds": round(uptime, 1),
            "packets_captured": self.flow_manager.total_packets_processed,
            "active_flows": len(self.flow_manager.active_flows),
            "completed_flows": self.flow_manager.total_flows_completed,
            "packets_per_sec": round(self.flow_manager.total_packets_processed / max(uptime, 1.0), 2)
        }

    def _on_packet(self, packet: Any) -> None:
        """Packet handler invoked by Scapy AsyncSniffer."""
        if not self._is_running:
            return

        try:
            completed = self.flow_manager.process_packet(packet)
            for flow in completed:
                if self.flow_callback:
                    self.flow_callback(flow)
        except Exception as e:
            logger.debug(f"Packet handling error: {e}")

    def _timeout_sweeper(self) -> None:
        """Background thread sweeping expired flows every 2 seconds."""
        while not self._stop_event.is_set():
            time.sleep(2.0)
            if not self._is_running:
                break
            try:
                now = time.time()
                timed_out = self.flow_manager.check_timeouts(current_time=now)
                for flow in timed_out:
                    if self.flow_callback:
                        self.flow_callback(flow)
            except Exception as e:
                logger.debug(f"Timeout sweep error: {e}")
