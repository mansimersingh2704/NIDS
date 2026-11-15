import React, { useEffect, useState } from 'react';
import {
  FileText,
  Download,
  Shield,
  Layers,
  AlertTriangle,
  Activity,
  CheckCircle2,
} from 'lucide-react';
import { api } from '../services/api';

export const ReportsPage: React.FC = () => {
  const [summaryData, setSummaryData] = useState<any>(null);
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    api.getReportSummary()
      .then((res) => setSummaryData(res.data))
      .catch((err) => console.error('Error fetching report summary:', err))
      .finally(() => setLoading(false));
  }, []);

  if (loading || !summaryData) {
    return (
      <div className="flex items-center justify-center h-full text-slate-400 font-mono text-sm">
        <Activity className="w-5 h-5 animate-spin mr-2 text-blue-400" />
        Generating executive report...
      </div>
    );
  }

  const traffic = summaryData.traffic_summary || {};

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-2 border-b border-navy-700/60">
        <div>
          <h1 className="text-xl font-bold text-slate-100 tracking-tight">Security Analytics & Forensic Reports</h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Export structured forensic logs and executive summary reports for incident response.
          </p>
        </div>
      </div>

      {/* Export Action Card */}
      <div className="p-6 rounded-xl bg-navy-850 border border-navy-700/80">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h3 className="text-sm font-bold text-slate-100">Export Raw Investigation Logs</h3>
            <p className="text-xs text-slate-400 mt-1">
              Download CSV data formatted for SIEM integration, audit compliance, or external forensic tools.
            </p>
          </div>
          <div className="flex items-center space-x-3">
            <a
              href={api.getExportUrl('flows')}
              className="px-4 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold flex items-center space-x-2 transition-colors shadow-sm"
            >
              <Download className="w-4 h-4" />
              <span>Download Flows CSV</span>
            </a>
            <a
              href={api.getExportUrl('alerts')}
              className="px-4 py-2.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold flex items-center space-x-2 transition-colors shadow-sm"
            >
              <Download className="w-4 h-4" />
              <span>Download Alerts CSV</span>
            </a>
          </div>
        </div>
      </div>

      {/* Executive Summary Sheet */}
      <div className="p-6 rounded-xl bg-navy-850 border border-navy-700/80 space-y-6">
        <div className="border-b border-navy-700/60 pb-4 flex items-center justify-between">
          <div>
            <span className="text-[11px] font-mono uppercase tracking-wider text-blue-400 font-bold">
              SOC Executive Briefing
            </span>
            <h2 className="text-lg font-bold text-slate-100 mt-0.5">{summaryData.report_title}</h2>
          </div>
          <div className="text-right text-xs font-mono text-slate-400">
            <div>Passive Surveillance Mode: <span className="text-emerald-400 font-bold">ACTIVE</span></div>
            <div>Classification Engine: <span className="text-slate-200">XGBoost & Random Forest</span></div>
          </div>
        </div>

        {/* Aggregate Stats */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="p-4 rounded-lg bg-navy-900 border border-navy-700">
            <span className="text-slate-400 text-xs font-mono block">Analyzed Wire Packets</span>
            <span className="text-xl font-bold font-mono text-slate-100 mt-1 block">
              {(traffic.total_packets || 0).toLocaleString()}
            </span>
          </div>
          <div className="p-4 rounded-lg bg-navy-900 border border-navy-700">
            <span className="text-slate-400 text-xs font-mono block">Directional Flows</span>
            <span className="text-xl font-bold font-mono text-purple-400 mt-1 block">
              {(traffic.total_flows || 0).toLocaleString()}
            </span>
          </div>
          <div className="p-4 rounded-lg bg-navy-900 border border-navy-700">
            <span className="text-slate-400 text-xs font-mono block">Benign Traffic Ratio</span>
            <span className="text-xl font-bold font-mono text-emerald-400 mt-1 block">
              {traffic.total_flows ? (((traffic.benign_flows || 0) / traffic.total_flows) * 100).toFixed(1) : 0}%
            </span>
          </div>
          <div className="p-4 rounded-lg bg-navy-900 border border-navy-700">
            <span className="text-slate-400 text-xs font-mono block">Threat Detection Rate</span>
            <span className="text-xl font-bold font-mono text-rose-400 mt-1 block">
              {(traffic.threat_detection_rate_pct || 0).toFixed(1)}%
            </span>
          </div>
        </div>

        {/* Detailed Breakdown Grids */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pt-2">
          {/* Threats Table */}
          <div className="p-4 rounded-lg bg-navy-900 border border-navy-700">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-300 font-mono mb-3">
              Identified Threat Vectors
            </h4>
            <div className="space-y-2 font-mono text-xs">
              {Object.entries(summaryData.attack_breakdown || {}).length > 0 ? (
                Object.entries(summaryData.attack_breakdown || {}).map(([cat, count]) => (
                  <div key={cat} className="flex justify-between py-1.5 border-b border-navy-800 last:border-0">
                    <span className="text-rose-400 font-semibold">{cat}</span>
                    <span className="text-slate-200">{count as number} flows</span>
                  </div>
                ))
              ) : (
                <div className="py-4 text-center text-slate-500">Zero active threat vectors detected.</div>
              )}
            </div>
          </div>

          {/* Protocols Table */}
          <div className="p-4 rounded-lg bg-navy-900 border border-navy-700">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-300 font-mono mb-3">
              Network Protocol Breakdown
            </h4>
            <div className="space-y-2 font-mono text-xs">
              {Object.entries(summaryData.protocol_breakdown || {}).map(([proto, count]) => (
                <div key={proto} className="flex justify-between py-1.5 border-b border-navy-800 last:border-0">
                  <span className="text-blue-400 font-semibold">{proto}</span>
                  <span className="text-slate-200">{count as number} flows</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
