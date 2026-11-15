import React from 'react';
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Layers,
  Radio,
  ShieldAlert,
  Zap,
} from 'lucide-react';
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { MetricCard } from '../components/MetricCard';
import { DashboardOverview, FlowRecord } from '../types/nids';

interface OverviewPageProps {
  overview: DashboardOverview | null;
  onNavigateToAlerts: () => void;
  onNavigateToLive: () => void;
}

export const OverviewPage: React.FC<OverviewPageProps> = ({
  overview,
  onNavigateToAlerts,
  onNavigateToLive,
}) => {
  if (!overview) {
    return (
      <div className="flex items-center justify-center h-full text-slate-400 font-mono text-sm">
        <Activity className="w-5 h-5 animate-spin mr-2 text-blue-400" />
        Loading SOC telemetry...
      </div>
    );
  }

  // Data for Benign vs Malicious Pie
  const pieData = [
    { name: 'Benign', value: overview.benign_count, color: '#10b981' },
    { name: 'Malicious', value: overview.malicious_count, color: '#ef4444' },
  ];

  // Data for Attack Distribution Bar Chart
  const attackData = Object.entries(overview.attack_distribution || {}).map(([name, count]) => ({
    name,
    count,
  }));

  // Data for Protocol Distribution
  const protocolData = Object.entries(overview.protocol_distribution || {}).map(([name, count]) => ({
    name,
    count,
  }));

  return (
    <div className="space-y-6">
      {/* Top Banner / Welcome */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-2 border-b border-navy-700/60">
        <div>
          <h1 className="text-xl font-bold text-slate-100 tracking-tight">Security Operations Overview</h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Real-time passive telemetry, AI threat classification, and directional flow metrics.
          </p>
        </div>
        <div className="mt-3 sm:mt-0 flex items-center space-x-3">
          <button
            onClick={onNavigateToLive}
            className="px-3.5 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold flex items-center space-x-1.5 transition-colors shadow-sm"
          >
            <Radio className="w-3.5 h-3.5" />
            <span>Open Live Tap</span>
          </button>
          <button
            onClick={onNavigateToAlerts}
            className="px-3.5 py-1.5 rounded-lg bg-navy-800 hover:bg-navy-700 border border-navy-700 text-slate-200 text-xs font-semibold flex items-center space-x-1.5 transition-colors"
          >
            <span>View Alerts ({overview.active_alerts})</span>
            <ArrowRight className="w-3.5 h-3.5 text-slate-400" />
          </button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
        <MetricCard
          title="Packets Captured"
          value={overview.total_packets.toLocaleString()}
          subtitle="Passive wire volume"
          icon={Activity}
          accentColor="blue"
        />
        <MetricCard
          title="Directional Flows"
          value={overview.total_flows.toLocaleString()}
          subtitle="Direction-isolated flows"
          icon={Layers}
          accentColor="purple"
        />
        <MetricCard
          title="Benign Traffic"
          value={overview.benign_count.toLocaleString()}
          subtitle="Legitimate sessions"
          icon={CheckCircle2}
          accentColor="green"
        />
        <MetricCard
          title="Malicious Traffic"
          value={overview.malicious_count.toLocaleString()}
          subtitle="Threat detections"
          icon={AlertTriangle}
          accentColor="rose"
        />
        <MetricCard
          title="Active Alerts"
          value={overview.active_alerts.toLocaleString()}
          subtitle="Deduplicated threats"
          icon={ShieldAlert}
          accentColor="amber"
        />
        <MetricCard
          title="Detection Rate"
          value={`${overview.detection_rate_pct.toFixed(1)}%`}
          subtitle="Malicious / Total flows"
          icon={Zap}
          accentColor={overview.detection_rate_pct > 10 ? 'rose' : 'blue'}
        />
      </div>

      {/* Analytical Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Traffic Over Time */}
        <div className="lg:col-span-2 p-5 rounded-xl bg-navy-850 border border-navy-700/80">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-semibold text-slate-200">Traffic Activity Timeline</h3>
              <p className="text-xs text-slate-400">Flow processing rate and threat volume over time</p>
            </div>
            <div className="flex items-center space-x-4 text-xs font-mono">
              <span className="flex items-center space-x-1.5 text-blue-400">
                <span className="w-2.5 h-2.5 rounded-full bg-blue-500" />
                <span>Total Flows</span>
              </span>
              <span className="flex items-center space-x-1.5 text-rose-400">
                <span className="w-2.5 h-2.5 rounded-full bg-rose-500" />
                <span>Malicious</span>
              </span>
            </div>
          </div>
          <div className="h-64">
            {overview.traffic_history && overview.traffic_history.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={overview.traffic_history}>
                  <defs>
                    <linearGradient id="totalFlows" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#3b82f6" stopOpacity={0.0} />
                    </linearGradient>
                    <linearGradient id="maliciousFlows" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#ef4444" stopOpacity={0.5} />
                      <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="time" stroke="#64748b" fontSize={11} />
                  <YAxis stroke="#64748b" fontSize={11} allowDecimals={false} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: 8 }}
                    itemStyle={{ color: '#f1f5f9' }}
                  />
                  <Area type="monotone" dataKey="total_flows" stroke="#3b82f6" strokeWidth={2} fill="url(#totalFlows)" name="Total Flows" />
                  <Area type="monotone" dataKey="malicious_flows" stroke="#ef4444" strokeWidth={2} fill="url(#maliciousFlows)" name="Malicious Flows" />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex flex-col items-center justify-center h-full text-slate-500 text-xs font-mono">
                <Layers className="w-8 h-8 mb-2 opacity-50" />
                <span>No traffic records in the current window. Start Live capture or analyze a PCAP.</span>
              </div>
            )}
          </div>
        </div>

        {/* Benign vs Malicious Donut */}
        <div className="p-5 rounded-xl bg-navy-850 border border-navy-700/80 flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-semibold text-slate-200">Traffic Composition</h3>
            <p className="text-xs text-slate-400">Classified Benign vs Threat proportion</p>
          </div>
          <div className="h-52 flex items-center justify-center my-2">
            {overview.total_flows > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={pieData}
                    cx="50%"
                    cy="50%"
                    innerRadius={55}
                    outerRadius={75}
                    paddingAngle={4}
                    dataKey="value"
                  >
                    {pieData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: 8 }}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="text-center text-slate-500 text-xs font-mono">No flow records yet</div>
            )}
          </div>
          <div className="grid grid-cols-2 gap-3 pt-3 border-t border-navy-700/60 font-mono text-xs">
            <div className="p-2.5 rounded-lg bg-navy-900 border border-navy-700">
              <span className="text-emerald-400 font-semibold block text-sm">{overview.benign_count}</span>
              <span className="text-slate-400 text-[11px]">Benign Flows</span>
            </div>
            <div className="p-2.5 rounded-lg bg-navy-900 border border-navy-700">
              <span className="text-rose-400 font-semibold block text-sm">{overview.malicious_count}</span>
              <span className="text-slate-400 text-[11px]">Threat Flows</span>
            </div>
          </div>
        </div>
      </div>

      {/* Attack Breakdown & Protocols */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Attack Category Breakdown */}
        <div className="p-5 rounded-xl bg-navy-850 border border-navy-700/80">
          <h3 className="text-sm font-semibold text-slate-200 mb-1">Detected Attack Categories</h3>
          <p className="text-xs text-slate-400 mb-4">Multi-class classification distribution</p>
          <div className="h-56">
            {attackData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={attackData} layout="vertical">
                  <XAxis type="number" stroke="#64748b" fontSize={11} allowDecimals={false} />
                  <YAxis type="category" dataKey="name" stroke="#64748b" fontSize={11} width={85} />
                  <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: 8 }} />
                  <Bar dataKey="count" fill="#ef4444" radius={[0, 4, 4, 0]} barSize={18} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex items-center justify-center h-full text-slate-500 text-xs font-mono">
                No attack categories detected yet.
              </div>
            )}
          </div>
        </div>

        {/* Protocol Distribution */}
        <div className="p-5 rounded-xl bg-navy-850 border border-navy-700/80">
          <h3 className="text-sm font-semibold text-slate-200 mb-1">Protocol Distribution</h3>
          <p className="text-xs text-slate-400 mb-4">Transport layer traffic composition</p>
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={protocolData}>
                <XAxis dataKey="name" stroke="#64748b" fontSize={11} />
                <YAxis stroke="#64748b" fontSize={11} allowDecimals={false} />
                <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: 8 }} />
                <Bar dataKey="count" fill="#3b82f6" radius={[4, 4, 0, 0]} barSize={24} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Recent Detection Activity Table */}
      <div className="p-5 rounded-xl bg-navy-850 border border-navy-700/80">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-sm font-semibold text-slate-200">Recent Detection Activity</h3>
            <p className="text-xs text-slate-400">Directional network flows analyzed by the ML engine</p>
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-navy-900 text-slate-400 uppercase text-[10px] tracking-wider border-b border-navy-700">
              <tr>
                <th className="py-2.5 px-3">Flow ID</th>
                <th className="py-2.5 px-3">Source</th>
                <th className="py-2.5 px-3">Destination</th>
                <th className="py-2.5 px-3">Proto</th>
                <th className="py-2.5 px-3">Packets / Bytes</th>
                <th className="py-2.5 px-3">Classification</th>
                <th className="py-2.5 px-3">Confidence</th>
                <th className="py-2.5 px-3">Risk</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-navy-700/60">
              {overview.recent_detections && overview.recent_detections.length > 0 ? (
                overview.recent_detections.slice(0, 8).map((f: FlowRecord) => (
                  <tr key={f.flow_id} className="hover:bg-navy-800/40 transition-colors">
                    <td className="py-2.5 px-3 font-semibold text-slate-300">{f.flow_id}</td>
                    <td className="py-2.5 px-3 text-slate-200">{f.src_ip}:{f.src_port}</td>
                    <td className="py-2.5 px-3 text-slate-200">{f.dst_ip}:{f.dst_port}</td>
                    <td className="py-2.5 px-3 text-slate-400">{f.protocol_name || f.protocol}</td>
                    <td className="py-2.5 px-3 text-slate-400">{f.total_packets} pkts / {f.total_bytes} B</td>
                    <td className="py-2.5 px-3">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold ${
                        f.is_malicious
                          ? 'bg-rose-500/15 text-rose-400 border border-rose-500/30'
                          : 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                      }`}>
                        {f.predicted_class}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-slate-300">{(f.confidence * 100).toFixed(1)}%</td>
                    <td className="py-2.5 px-3">
                      <span className={`font-semibold ${
                        f.risk_level === 'Critical' ? 'text-rose-500' :
                        f.risk_level === 'High' ? 'text-amber-400' :
                        f.risk_level === 'Medium' ? 'text-yellow-400' : 'text-emerald-400'
                      }`}>
                        {f.risk_level}
                      </span>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-500 font-mono text-xs">
                    No detections recorded yet. Launch live capture or upload a PCAP.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
