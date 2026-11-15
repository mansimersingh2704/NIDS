import React, { useEffect, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Play,
  Square,
  Shield,
  Layers,
  Clock,
  Radio,
} from 'lucide-react';
import { api } from '../services/api';
import { AlertItem, CaptureStatus, FlowRecord, NetworkInterface } from '../types/nids';

interface LiveMonitoringPageProps {
  liveFlows: FlowRecord[];
  liveAlerts: AlertItem[];
  captureStatus: CaptureStatus | null;
  onRefreshStatus: () => void;
}

export const LiveMonitoringPage: React.FC<LiveMonitoringPageProps> = ({
  liveFlows,
  liveAlerts,
  captureStatus,
  onRefreshStatus,
}) => {
  const [interfaces, setInterfaces] = useState<NetworkInterface[]>([]);
  const [selectedInterface, setSelectedInterface] = useState<string>('');
  const [loadingAction, setLoadingAction] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  useEffect(() => {
    api.getInterfaces()
      .then((res) => {
        setInterfaces(res.data);
        const def = res.data.find((i) => i.is_default);
        if (def) {
          setSelectedInterface(def.id);
        } else if (res.data.length > 0) {
          setSelectedInterface(res.data[0].id);
        }
      })
      .catch((err) => {
        console.error('Error fetching interfaces:', err);
      });
  }, []);

  const handleStartCapture = async () => {
    setLoadingAction(true);
    setErrorMessage(null);
    try {
      await api.startCapture(selectedInterface || undefined);
      onRefreshStatus();
    } catch (err: any) {
      const msg = err.response?.data?.detail || 'Failed to start live capture.';
      setErrorMessage(msg);
    } finally {
      setLoadingAction(false);
    }
  };

  const handleStopCapture = async () => {
    setLoadingAction(true);
    setErrorMessage(null);
    try {
      await api.stopCapture();
      onRefreshStatus();
    } catch (err: any) {
      const msg = err.response?.data?.detail || 'Failed to stop capture.';
      setErrorMessage(msg);
    } finally {
      setLoadingAction(false);
    }
  };

  const isRunning = captureStatus?.is_running ?? false;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-2 border-b border-navy-700/60">
        <div>
          <h1 className="text-xl font-bold text-slate-100 tracking-tight">Passive Live Traffic Monitor</h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Real-time passive wire sniffing, directional flow assembly, and streaming ML classification.
          </p>
        </div>
        <div className="mt-3 sm:mt-0 flex items-center space-x-2">
          <span className="inline-flex items-center space-x-1.5 px-3 py-1 rounded-full text-xs font-mono bg-navy-800 border border-navy-700 text-slate-300">
            <span className={`w-2 h-2 rounded-full ${isRunning ? 'bg-emerald-400 animate-pulse' : 'bg-slate-500'}`} />
            <span>MODE: {isRunning ? 'LIVE INTERFACE TAP' : 'OFFLINE / STANDBY'}</span>
          </span>
        </div>
      </div>

      {/* Control Panel Card */}
      <div className="p-5 rounded-xl bg-navy-850 border border-navy-700/80">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          {/* Interface Selector */}
          <div className="flex-1 max-w-xl">
            <label className="block text-xs font-medium text-slate-400 uppercase tracking-wider mb-1.5">
              Network Capture Adapter
            </label>
            <select
              value={selectedInterface}
              onChange={(e) => setSelectedInterface(e.target.value)}
              disabled={isRunning || loadingAction}
              className="w-full bg-navy-900 border border-navy-700 rounded-lg px-3.5 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-blue-500 disabled:opacity-50"
            >
              {interfaces.map((iface) => (
                <option key={iface.id} value={iface.id}>
                  {iface.name} {iface.is_default ? '(System Default)' : ''} {iface.is_loopback ? '(Loopback)' : ''}
                </option>
              ))}
            </select>
            <p className="text-[11px] text-slate-400 mt-1">
              * Operates exclusively in passive promiscuous capture. Packets are read off the wire without modification.
            </p>
          </div>

          {/* Action Buttons */}
          <div className="flex items-center space-x-3 pt-2 md:pt-0">
            {!isRunning ? (
              <button
                onClick={handleStartCapture}
                disabled={loadingAction}
                className="px-5 py-2.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold flex items-center space-x-2 transition-colors disabled:opacity-50 shadow-sm"
              >
                <Play className="w-4 h-4 fill-current" />
                <span>Start Monitoring</span>
              </button>
            ) : (
              <button
                onClick={handleStopCapture}
                disabled={loadingAction}
                className="px-5 py-2.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold flex items-center space-x-2 transition-colors disabled:opacity-50 shadow-sm"
              >
                <Square className="w-4 h-4 fill-current" />
                <span>Stop Monitoring</span>
              </button>
            )}
          </div>
        </div>

        {errorMessage && (
          <div className="mt-4 p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs flex items-center space-x-2">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>{errorMessage}</span>
          </div>
        )}
      </div>

      {/* Live Telemetry Stats */}
      {captureStatus && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="p-4 rounded-xl bg-navy-850 border border-navy-700/80">
            <div className="flex items-center space-x-2 text-slate-400 text-xs mb-1">
              <Clock className="w-3.5 h-3.5" />
              <span>Capture Uptime</span>
            </div>
            <div className="text-xl font-bold font-mono text-slate-100">{captureStatus.uptime_seconds.toFixed(1)}s</div>
          </div>
          <div className="p-4 rounded-xl bg-navy-850 border border-navy-700/80">
            <div className="flex items-center space-x-2 text-slate-400 text-xs mb-1">
              <Activity className="w-3.5 h-3.5 text-blue-400" />
              <span>Packets Captured</span>
            </div>
            <div className="text-xl font-bold font-mono text-blue-400">{captureStatus.packets_captured.toLocaleString()}</div>
          </div>
          <div className="p-4 rounded-xl bg-navy-850 border border-navy-700/80">
            <div className="flex items-center space-x-2 text-slate-400 text-xs mb-1">
              <Layers className="w-3.5 h-3.5 text-purple-400" />
              <span>Active Directional Flows</span>
            </div>
            <div className="text-xl font-bold font-mono text-purple-400">{captureStatus.active_flows}</div>
          </div>
          <div className="p-4 rounded-xl bg-navy-850 border border-navy-700/80">
            <div className="flex items-center space-x-2 text-slate-400 text-xs mb-1">
              <Radio className="w-3.5 h-3.5 text-emerald-400" />
              <span>Throughput Rate</span>
            </div>
            <div className="text-xl font-bold font-mono text-emerald-400">{captureStatus.packets_per_sec.toFixed(1)} pkt/s</div>
          </div>
        </div>
      )}

      {/* Real-time Streaming Grids: Live Alerts & Live Flow Feed */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Real-time Alert Feed */}
        <div className="p-5 rounded-xl bg-navy-850 border border-navy-700/80 flex flex-col h-[520px]">
          <div className="flex items-center justify-between pb-3 border-b border-navy-700/60 mb-3">
            <div className="flex items-center space-x-2">
              <Shield className="w-4 h-4 text-rose-400" />
              <h3 className="text-sm font-semibold text-slate-200">Live Alert Stream</h3>
            </div>
            <span className="text-[11px] font-mono font-semibold px-2 py-0.5 rounded-full bg-rose-500/10 text-rose-400 border border-rose-500/20">
              {liveAlerts.length} Active
            </span>
          </div>

          <div className="flex-1 overflow-y-auto space-y-2.5 pr-1">
            {liveAlerts.length > 0 ? (
              liveAlerts.map((alt) => (
                <div
                  key={alt.alert_id}
                  className="p-3 rounded-lg bg-navy-900 border border-navy-700 hover:border-navy-600 transition-colors"
                >
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="font-mono text-xs font-bold text-slate-200">{alt.attack_type}</span>
                    <span className={`text-[10px] uppercase font-bold px-1.5 py-0.5 rounded ${
                      alt.severity === 'Critical' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' :
                      alt.severity === 'High' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                      alt.severity === 'Medium' ? 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30' :
                      'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                    }`}>
                      {alt.severity}
                    </span>
                  </div>
                  <div className="font-mono text-[11px] text-slate-400">
                    <div>Src: <span className="text-slate-300">{alt.source_ip}:{alt.source_port}</span></div>
                    <div>Dst: <span className="text-slate-300">{alt.destination_ip}:{alt.destination_port}</span></div>
                  </div>
                  <div className="flex items-center justify-between mt-2 pt-2 border-t border-navy-800 text-[10px] font-mono text-slate-400">
                    <span>Conf: {(alt.confidence * 100).toFixed(0)}%</span>
                    <span>Count: {alt.occurrence_count}</span>
                  </div>
                </div>
              ))
            ) : (
              <div className="flex flex-col items-center justify-center h-full text-slate-500 text-xs font-mono text-center px-4">
                <CheckCircle2 className="w-8 h-8 mb-2 text-emerald-500/50" />
                <span>Zero intrusion alerts triggered. Network perimeter clear.</span>
              </div>
            )}
          </div>
        </div>

        {/* Live Streaming Flow Feed */}
        <div className="lg:col-span-2 p-5 rounded-xl bg-navy-850 border border-navy-700/80 flex flex-col h-[520px]">
          <div className="flex items-center justify-between pb-3 border-b border-navy-700/60 mb-3">
            <div className="flex items-center space-x-2">
              <Activity className="w-4 h-4 text-blue-400" />
              <h3 className="text-sm font-semibold text-slate-200">Streaming Directional Flow Table</h3>
            </div>
            <span className="text-[11px] font-mono text-slate-400">
              Auto-updating via WebSocket
            </span>
          </div>

          <div className="flex-1 overflow-x-auto overflow-y-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-navy-900 text-slate-400 uppercase text-[10px] tracking-wider sticky top-0 border-b border-navy-700">
                <tr>
                  <th className="py-2 px-3">Flow ID</th>
                  <th className="py-2 px-3">Direction</th>
                  <th className="py-2 px-3">Proto</th>
                  <th className="py-2 px-3">Duration</th>
                  <th className="py-2 px-3">Packets / Bytes</th>
                  <th className="py-2 px-3">Classification</th>
                  <th className="py-2 px-3">Confidence</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-navy-700/50">
                {liveFlows.length > 0 ? (
                  liveFlows.map((f) => (
                    <tr key={f.flow_id} className="hover:bg-navy-800/40 transition-colors">
                      <td className="py-2 px-3 text-slate-300 font-semibold">{f.flow_id}</td>
                      <td className="py-2 px-3 text-slate-200">
                        {f.src_ip}:{f.src_port} &rarr; {f.dst_ip}:{f.dst_port}
                      </td>
                      <td className="py-2 px-3 text-slate-400">{f.protocol_name || f.protocol}</td>
                      <td className="py-2 px-3 text-slate-400">{f.duration_sec.toFixed(3)}s</td>
                      <td className="py-2 px-3 text-slate-400">{f.total_packets} pkts / {f.total_bytes} B</td>
                      <td className="py-2 px-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          f.is_malicious
                            ? 'bg-rose-500/15 text-rose-400 border border-rose-500/30'
                            : 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                        }`}>
                          {f.predicted_class}
                        </span>
                      </td>
                      <td className="py-2 px-3 text-slate-300">{(f.confidence * 100).toFixed(1)}%</td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={7} className="py-16 text-center text-slate-500 font-mono text-xs">
                      Awaiting live traffic packets...
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};
