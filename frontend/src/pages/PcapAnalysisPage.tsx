import React, { useEffect, useState } from 'react';
import {
  UploadCloud,
  FileSpreadsheet,
  CheckCircle2,
  AlertTriangle,
  Play,
  Download,
  Activity,
  Layers,
  ShieldAlert,
} from 'lucide-react';
import { api } from '../services/api';
import { FlowRecord, SamplePcap } from '../types/nids';

interface PcapAnalysisResult {
  success: boolean;
  filename: string;
  packets_count: number;
  flows_count: number;
  benign_count: number;
  malicious_count: number;
  attacks_detected: Record<string, number>;
  processing_time_sec: number;
  alerts_generated: number;
  detections: FlowRecord[];
}

export const PcapAnalysisPage: React.FC = () => {
  const [samples, setSamples] = useState<SamplePcap[]>([]);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [selectedSample, setSelectedSample] = useState<string>('');
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [analysisResult, setAnalysisResult] = useState<PcapAnalysisResult | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  useEffect(() => {
    api.getSamplePcaps()
      .then((res) => setSamples(res.data.samples || []))
      .catch((err) => console.error('Error fetching sample pcaps:', err));
  }, []);

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      const ext = file.name.split('.').pop()?.toLowerCase();
      if (!['pcap', 'pcapng', 'cap'].includes(ext || '')) {
        setErrorMessage('Invalid file format. Please select a valid .pcap or .pcapng file.');
        return;
      }
      setSelectedFile(file);
      setSelectedSample('');
      setErrorMessage(null);
    }
  };

  const handleRunAnalysis = async () => {
    setIsAnalyzing(true);
    setErrorMessage(null);

    try {
      let targetFilename = selectedSample;

      if (selectedFile) {
        // Upload first
        const uploadRes = await api.uploadPcap(selectedFile);
        targetFilename = uploadRes.data.filename;
      }

      if (!targetFilename) {
        setErrorMessage('Please choose or upload a PCAP file first.');
        setIsAnalyzing(false);
        return;
      }

      const res = await api.analyzePcap(targetFilename);
      setAnalysisResult(res.data);
    } catch (err: any) {
      setErrorMessage(err.response?.data?.detail || 'Failed to analyze PCAP file.');
    } finally {
      setIsAnalyzing(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-2 border-b border-navy-700/60">
        <div>
          <h1 className="text-xl font-bold text-slate-100 tracking-tight">Offline PCAP Forensic Analysis</h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Extracts directional NetFlow statistics and executes machine learning inference on packet captures.
          </p>
        </div>
      </div>

      {/* Upload and Selection Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Custom PCAP Upload */}
        <div className="p-6 rounded-xl bg-navy-850 border border-navy-700/80 flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-semibold text-slate-200 mb-1">Upload PCAP / PCAPNG File</h3>
            <p className="text-xs text-slate-400 mb-4">
              Passive security audit of standard Wireshark/tcpdump captures (Max: 50MB).
            </p>

            <label className="border-2 border-dashed border-navy-700 hover:border-blue-500/50 rounded-xl p-6 flex flex-col items-center justify-center cursor-pointer transition-colors bg-navy-900/40">
              <UploadCloud className="w-8 h-8 text-blue-400 mb-2" />
              <span className="text-xs font-medium text-slate-300">
                {selectedFile ? selectedFile.name : 'Click to browse or drop PCAP file here'}
              </span>
              <span className="text-[11px] text-slate-400 mt-1 font-mono">
                {selectedFile ? `${(selectedFile.size / 1024).toFixed(1)} KB` : 'Supports .pcap, .pcapng, .cap'}
              </span>
              <input type="file" accept=".pcap,.pcapng,.cap" onChange={handleFileUpload} className="hidden" />
            </label>
          </div>

          <div className="mt-4 flex items-center justify-between">
            <span className="text-xs text-slate-400 font-mono">
              {selectedFile ? 'Ready for inference' : 'No file chosen'}
            </span>
            <button
              onClick={handleRunAnalysis}
              disabled={(!selectedFile && !selectedSample) || isAnalyzing}
              className="px-5 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold flex items-center space-x-2 transition-colors disabled:opacity-50 shadow-sm"
            >
              {isAnalyzing ? (
                <>
                  <Activity className="w-4 h-4 animate-spin" />
                  <span>Processing Flows...</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 fill-current" />
                  <span>Analyze Capture</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Pre-packaged Portfolio Sample PCAPs */}
        <div className="p-6 rounded-xl bg-navy-850 border border-navy-700/80 flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-semibold text-slate-200 mb-1">Sample PCAP Library</h3>
            <p className="text-xs text-slate-400 mb-4">
              Pre-built network capture benchmarks for instantaneous evaluation and testing.
            </p>

            <div className="space-y-2.5 max-h-52 overflow-y-auto pr-1">
              {samples.map((s) => {
                const isSelected = selectedSample === s.filename;
                return (
                  <div
                    key={s.filename}
                    onClick={() => {
                      setSelectedSample(s.filename);
                      setSelectedFile(null);
                      setErrorMessage(null);
                    }}
                    className={`p-3 rounded-lg border cursor-pointer transition-colors ${
                      isSelected
                        ? 'bg-blue-600/15 border-blue-500/40 text-blue-300'
                        : 'bg-navy-900 border-navy-700 hover:border-navy-600 text-slate-300'
                    }`}
                  >
                    <div className="flex items-center justify-between font-mono text-xs font-semibold mb-1">
                      <span>{s.filename}</span>
                      <span className="text-[11px] text-slate-400">{(s.size_bytes / 1024).toFixed(1)} KB</span>
                    </div>
                    <p className="text-[11px] text-slate-400">{s.description}</p>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="mt-4 flex items-center justify-between">
            <span className="text-xs text-slate-400 font-mono">
              {selectedSample ? `Selected: ${selectedSample}` : 'Select a sample file'}
            </span>
            <button
              onClick={handleRunAnalysis}
              disabled={(!selectedFile && !selectedSample) || isAnalyzing}
              className="px-5 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold flex items-center space-x-2 transition-colors disabled:opacity-50 shadow-sm"
            >
              <Play className="w-4 h-4 fill-current" />
              <span>Analyze Selected</span>
            </button>
          </div>
        </div>
      </div>

      {errorMessage && (
        <div className="p-3.5 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs flex items-center space-x-2">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <span>{errorMessage}</span>
        </div>
      )}

      {/* Analysis Results Display */}
      {analysisResult && (
        <div className="space-y-6 pt-2">
          <div className="flex items-center justify-between">
            <h2 className="text-base font-bold text-slate-100">
              Analysis Results &mdash; <span className="font-mono text-blue-400">{analysisResult.filename}</span>
            </h2>
            <div className="flex items-center space-x-2 text-xs font-mono text-slate-400">
              <span>Execution Time: <span className="text-slate-200">{analysisResult.processing_time_sec.toFixed(3)}s</span></span>
            </div>
          </div>

          {/* KPI Grid */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            <div className="p-4 rounded-xl bg-navy-850 border border-navy-700/80">
              <span className="text-xs text-slate-400 uppercase font-mono">Total Packets</span>
              <div className="text-xl font-bold font-mono text-slate-100 mt-1">{analysisResult.packets_count.toLocaleString()}</div>
            </div>
            <div className="p-4 rounded-xl bg-navy-850 border border-navy-700/80">
              <span className="text-xs text-slate-400 uppercase font-mono">Directional Flows</span>
              <div className="text-xl font-bold font-mono text-purple-400 mt-1">{analysisResult.flows_count.toLocaleString()}</div>
            </div>
            <div className="p-4 rounded-xl bg-navy-850 border border-navy-700/80">
              <span className="text-xs text-slate-400 uppercase font-mono">Benign Flows</span>
              <div className="text-xl font-bold font-mono text-emerald-400 mt-1">{analysisResult.benign_count.toLocaleString()}</div>
            </div>
            <div className="p-4 rounded-xl bg-navy-850 border border-navy-700/80">
              <span className="text-xs text-slate-400 uppercase font-mono">Malicious Flows</span>
              <div className="text-xl font-bold font-mono text-rose-400 mt-1">{analysisResult.malicious_count.toLocaleString()}</div>
            </div>
            <div className="p-4 rounded-xl bg-navy-850 border border-navy-700/80">
              <span className="text-xs text-slate-400 uppercase font-mono">Alerts Triggered</span>
              <div className="text-xl font-bold font-mono text-amber-400 mt-1">{analysisResult.alerts_generated}</div>
            </div>
          </div>

          {/* Attack Breakdown Pill Badges */}
          {Object.keys(analysisResult.attacks_detected).length > 0 && (
            <div className="p-4 rounded-xl bg-navy-850 border border-navy-700/80 flex items-center space-x-3">
              <span className="text-xs font-semibold text-slate-300 font-mono">Detected Attacks:</span>
              <div className="flex flex-wrap gap-2">
                {Object.entries(analysisResult.attacks_detected).map(([atk, count]) => (
                  <span
                    key={atk}
                    className="px-2.5 py-1 rounded-md text-xs font-mono font-bold bg-rose-500/15 border border-rose-500/30 text-rose-400"
                  >
                    {atk}: {count} flow{count > 1 ? 's' : ''}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Detections Table */}
          <div className="p-5 rounded-xl bg-navy-850 border border-navy-700/80">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-sm font-semibold text-slate-200">Extracted Directional Flows</h3>
                <p className="text-xs text-slate-400">Classified flows from PCAP capture</p>
              </div>
              <a
                href={api.getExportUrl('flows')}
                className="px-3 py-1.5 rounded-lg bg-navy-800 hover:bg-navy-700 border border-navy-700 text-slate-200 text-xs font-semibold flex items-center space-x-1.5 transition-colors"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Export CSV</span>
              </a>
            </div>

            <div className="overflow-x-auto max-h-96">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-navy-900 text-slate-400 uppercase text-[10px] tracking-wider sticky top-0 border-b border-navy-700">
                  <tr>
                    <th className="py-2.5 px-3">Direction</th>
                    <th className="py-2.5 px-3">Proto</th>
                    <th className="py-2.5 px-3">Duration</th>
                    <th className="py-2.5 px-3">Packets / Bytes</th>
                    <th className="py-2.5 px-3">Classification</th>
                    <th className="py-2.5 px-3">Confidence</th>
                    <th className="py-2.5 px-3">Risk Level</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-navy-700/50">
                  {analysisResult.detections.map((d) => (
                    <tr key={d.flow_id} className="hover:bg-navy-800/40 transition-colors">
                      <td className="py-2.5 px-3 text-slate-200">
                        {d.src_ip}:{d.src_port} &rarr; {d.dst_ip}:{d.dst_port}
                      </td>
                      <td className="py-2.5 px-3 text-slate-400">{d.protocol_name || d.protocol}</td>
                      <td className="py-2.5 px-3 text-slate-400">{d.duration_sec.toFixed(3)}s</td>
                      <td className="py-2.5 px-3 text-slate-400">{d.total_packets} pkts / {d.total_bytes} B</td>
                      <td className="py-2.5 px-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          d.is_malicious
                            ? 'bg-rose-500/15 text-rose-400 border border-rose-500/30'
                            : 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                        }`}>
                          {d.predicted_class}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-slate-300">{(d.confidence * 100).toFixed(1)}%</td>
                      <td className="py-2.5 px-3">
                        <span className={`font-semibold ${
                          d.risk_level === 'Critical' ? 'text-rose-500' :
                          d.risk_level === 'High' ? 'text-amber-400' :
                          d.risk_level === 'Medium' ? 'text-yellow-400' : 'text-emerald-400'
                        }`}>
                          {d.risk_level}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
