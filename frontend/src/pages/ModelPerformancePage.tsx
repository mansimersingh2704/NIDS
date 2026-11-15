import React, { useEffect, useState } from 'react';
import {
  Cpu,
  BarChart2,
  CheckCircle2,
  Database,
  Layers,
  Zap,
  Activity,
  ArrowRightLeft,
} from 'lucide-react';
import {
  Bar,
  BarChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { api } from '../services/api';
import { ModelInfo } from '../types/nids';

export const ModelPerformancePage: React.FC = () => {
  const [modelInfo, setModelInfo] = useState<ModelInfo | null>(null);
  const [selectedModel, setSelectedModel] = useState<string>('random_forest');
  const [loading, setLoading] = useState<boolean>(true);
  const [switching, setSwitching] = useState<boolean>(false);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);

  const fetchModelData = () => {
    setLoading(true);
    api.getModelInfo()
      .then((res) => {
        setModelInfo(res.data);
        setSelectedModel(res.data.active_model);
      })
      .catch((err) => console.error('Error fetching model info:', err))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchModelData();
  }, []);

  const handleSwitchModel = async (modelName: string) => {
    setSwitching(true);
    setStatusMessage(null);
    try {
      await api.switchModel(modelName);
      setSelectedModel(modelName);
      setStatusMessage(`Active detection engine switched to ${modelName.toUpperCase()}.`);
      fetchModelData();
    } catch (err: any) {
      setStatusMessage(err.response?.data?.detail || 'Failed to switch model.');
    } finally {
      setSwitching(false);
    }
  };

  if (loading || !modelInfo) {
    return (
      <div className="flex items-center justify-center h-full text-slate-400 font-mono text-sm">
        <Activity className="w-5 h-5 animate-spin mr-2 text-blue-400" />
        Loading model performance metrics...
      </div>
    );
  }

  const modelMeta = modelInfo.metadata?.models?.[selectedModel];
  const metrics = modelMeta?.metrics;
  const confusion = metrics?.confusion_matrix;
  const classes = confusion?.classes || modelInfo.classes || [];

  // Top 10 feature importances for chart
  const importanceEntries = Object.entries(modelMeta?.feature_importances || {}).slice(0, 10);
  const importanceData = importanceEntries.map(([name, val]) => ({
    name,
    importance: val,
  }));

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-2 border-b border-navy-700/60">
        <div>
          <h1 className="text-xl font-bold text-slate-100 tracking-tight">Machine Learning Evaluation & Telemetry</h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Empirical test set metrics from real CIC-IDS2017 benchmark evaluation (15% held-out test split).
          </p>
        </div>
        <div className="mt-3 sm:mt-0 flex items-center space-x-2">
          <span className="text-xs font-mono text-slate-400 mr-2">Active Model:</span>
          {modelInfo.available_models.map((m) => (
            <button
              key={m}
              onClick={() => handleSwitchModel(m)}
              disabled={switching || modelInfo.active_model === m}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition-colors ${
                modelInfo.active_model === m
                  ? 'bg-blue-600 text-white shadow-sm border border-blue-500'
                  : 'bg-navy-800 text-slate-400 hover:text-slate-200 border border-navy-700'
              }`}
            >
              {m.toUpperCase()}
            </button>
          ))}
        </div>
      </div>

      {statusMessage && (
        <div className="p-3 rounded-lg bg-blue-500/10 border border-blue-500/30 text-blue-400 text-xs font-mono flex items-center space-x-2">
          <CheckCircle2 className="w-4 h-4 shrink-0" />
          <span>{statusMessage}</span>
        </div>
      )}

      {/* Model Overview Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-navy-850 border border-navy-700/80">
          <span className="text-xs text-slate-400 uppercase font-mono">Algorithm Family</span>
          <div className="text-lg font-bold font-mono text-slate-100 mt-1">{modelMeta?.type || 'Ensemble'}</div>
          <p className="text-[11px] text-slate-400 mt-0.5">{modelMeta?.name || selectedModel}</p>
        </div>
        <div className="p-4 rounded-xl bg-navy-850 border border-navy-700/80">
          <span className="text-xs text-slate-400 uppercase font-mono">Test Accuracy</span>
          <div className="text-2xl font-bold font-mono text-emerald-400 mt-1">
            {metrics ? (metrics.accuracy * 100).toFixed(2) : 0}%
          </div>
          <p className="text-[11px] text-slate-400 mt-0.5">Held-out test split</p>
        </div>
        <div className="p-4 rounded-xl bg-navy-850 border border-navy-700/80">
          <span className="text-xs text-slate-400 uppercase font-mono">Macro F1-Score</span>
          <div className="text-2xl font-bold font-mono text-blue-400 mt-1">
            {metrics ? (metrics.f1_macro * 100).toFixed(2) : 0}%
          </div>
          <p className="text-[11px] text-slate-400 mt-0.5">Unweighted multi-class</p>
        </div>
        <div className="p-4 rounded-xl bg-navy-850 border border-navy-700/80">
          <span className="text-xs text-slate-400 uppercase font-mono">False Positive Rate</span>
          <div className="text-2xl font-bold font-mono text-purple-400 mt-1">
            {metrics ? (metrics.false_positive_rate * 100).toFixed(3) : 0}%
          </div>
          <p className="text-[11px] text-slate-400 mt-0.5">Benign misclassification</p>
        </div>
      </div>

      {/* Metrics Comparison & Training Dataset Details */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Model Comparison Table */}
        <div className="lg:col-span-2 p-5 rounded-xl bg-navy-850 border border-navy-700/80">
          <h3 className="text-sm font-semibold text-slate-200 mb-1">Model Evaluation Benchmark</h3>
          <p className="text-xs text-slate-400 mb-4">
            Comparison between Random Forest and XGBoost across the exact same test partition.
          </p>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-navy-900 text-slate-400 uppercase text-[10px] tracking-wider border-b border-navy-700">
                <tr>
                  <th className="py-2.5 px-3">Model</th>
                  <th className="py-2.5 px-3">Accuracy</th>
                  <th className="py-2.5 px-3">Precision (Macro)</th>
                  <th className="py-2.5 px-3">Recall (Macro)</th>
                  <th className="py-2.5 px-3">Macro F1</th>
                  <th className="py-2.5 px-3">FPR</th>
                  <th className="py-2.5 px-3 text-right">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-navy-700/50">
                {Object.entries(modelInfo.metadata?.models || {}).map(([key, m]: [string, any]) => {
                  if (key === 'isolation_forest') return null;
                  const isCurrent = modelInfo.active_model === key;
                  return (
                    <tr key={key} className={isCurrent ? 'bg-blue-600/10' : 'hover:bg-navy-800/40'}>
                      <td className="py-2.5 px-3 font-bold text-slate-200">{m.name}</td>
                      <td className="py-2.5 px-3 text-emerald-400 font-semibold">
                        {(m.metrics.accuracy * 100).toFixed(2)}%
                      </td>
                      <td className="py-2.5 px-3 text-slate-300">
                        {(m.metrics.precision_macro * 100).toFixed(2)}%
                      </td>
                      <td className="py-2.5 px-3 text-slate-300">
                        {(m.metrics.recall_macro * 100).toFixed(2)}%
                      </td>
                      <td className="py-2.5 px-3 text-blue-400 font-semibold">
                        {(m.metrics.f1_macro * 100).toFixed(2)}%
                      </td>
                      <td className="py-2.5 px-3 text-slate-400">
                        {(m.metrics.false_positive_rate * 100).toFixed(3)}%
                      </td>
                      <td className="py-2.5 px-3 text-right">
                        {isCurrent ? (
                          <span className="px-2 py-0.5 rounded bg-blue-500/20 text-blue-400 border border-blue-500/30 text-[10px] font-bold">
                            ACTIVE
                          </span>
                        ) : (
                          <button
                            onClick={() => handleSwitchModel(key)}
                            className="px-2 py-0.5 rounded bg-navy-800 hover:bg-navy-700 text-slate-300 text-[10px] font-semibold"
                          >
                            Activate
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* Training Dataset Metadata Card */}
        <div className="p-5 rounded-xl bg-navy-850 border border-navy-700/80 flex flex-col justify-between">
          <div>
            <div className="flex items-center space-x-2 mb-2">
              <Database className="w-4 h-4 text-indigo-400" />
              <h3 className="text-sm font-semibold text-slate-200">Dataset Partitioning</h3>
            </div>
            <p className="text-xs text-slate-400 mb-4 font-mono">
              Dataset: <span className="text-slate-200 font-bold">{modelInfo.dataset}</span>
            </p>

            <div className="space-y-3 font-mono text-xs">
              <div className="flex justify-between pb-2 border-b border-navy-700/60">
                <span className="text-slate-400">Total Cleaned Flows</span>
                <span className="text-slate-200 font-semibold">{modelInfo.total_training_samples.toLocaleString()}</span>
              </div>
              <div className="flex justify-between pb-2 border-b border-navy-700/60">
                <span className="text-slate-400">Training Split (70%)</span>
                <span className="text-slate-200 font-semibold">{modelInfo.metadata?.train_samples?.toLocaleString()}</span>
              </div>
              <div className="flex justify-between pb-2 border-b border-navy-700/60">
                <span className="text-slate-400">Validation Split (15%)</span>
                <span className="text-slate-200 font-semibold">{modelInfo.metadata?.val_samples?.toLocaleString()}</span>
              </div>
              <div className="flex justify-between pb-2 border-b border-navy-700/60">
                <span className="text-slate-400">Test Split (15%)</span>
                <span className="text-emerald-400 font-semibold">{modelInfo.metadata?.test_samples?.toLocaleString()}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Input Feature Count</span>
                <span className="text-indigo-400 font-semibold">{modelInfo.features_count}</span>
              </div>
            </div>
          </div>

          <div className="mt-4 p-3 rounded-lg bg-navy-900 border border-navy-700 text-[11px] text-slate-400 leading-relaxed">
            * Isolation Forest is additionally trained on Benign baselines to detect zero-day statistical outliers.
          </div>
        </div>
      </div>

      {/* Visual Confusion Matrix & Feature Importances */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Confusion Matrix Heatmap Table */}
        <div className="p-5 rounded-xl bg-navy-850 border border-navy-700/80">
          <h3 className="text-sm font-semibold text-slate-200 mb-1">
            Empirical Confusion Matrix &mdash; <span className="font-mono text-blue-400">{modelMeta?.name}</span>
          </h3>
          <p className="text-xs text-slate-400 mb-4">
            Actual Ground Truth (Rows) vs Model Predicted Label (Columns)
          </p>

          {confusion && confusion.matrix ? (
            <div className="overflow-x-auto">
              <table className="w-full text-center text-xs font-mono border-collapse">
                <thead>
                  <tr className="bg-navy-900 text-slate-400 text-[10px] uppercase">
                    <th className="p-3 text-left">Actual \ Pred</th>
                    {classes.map((cls) => (
                      <th key={cls} className="p-3">{cls}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-navy-700/60">
                  {classes.map((actualClass, rowIdx) => (
                    <tr key={actualClass}>
                      <td className="p-3 text-left font-bold text-slate-300 bg-navy-900/60">{actualClass}</td>
                      {confusion.matrix[rowIdx]?.map((val, colIdx) => {
                        const isDiagonal = rowIdx === colIdx;
                        return (
                          <td
                            key={colIdx}
                            className={`p-3 font-semibold ${
                              isDiagonal
                                ? 'bg-emerald-950/40 text-emerald-400 border border-emerald-900/40'
                                : val > 0
                                ? 'bg-rose-950/40 text-rose-400 border border-rose-900/40'
                                : 'text-slate-600'
                            }`}
                          >
                            {val.toLocaleString()}
                          </td>
                        );
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="flex items-center justify-center h-48 text-slate-500 text-xs font-mono">
              Confusion matrix unavailable.
            </div>
          )}
        </div>

        {/* Feature Importance Bar Chart */}
        <div className="p-5 rounded-xl bg-navy-850 border border-navy-700/80">
          <h3 className="text-sm font-semibold text-slate-200 mb-1">Top Predictive Flow Features</h3>
          <p className="text-xs text-slate-400 mb-4">Gini importance computed across decision tree ensembles</p>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={importanceData} layout="vertical">
                <XAxis type="number" stroke="#64748b" fontSize={11} />
                <YAxis type="category" dataKey="name" stroke="#64748b" fontSize={10} width={130} />
                <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: 8 }} />
                <Bar dataKey="importance" fill="#8b5cf6" radius={[0, 4, 4, 0]} barSize={14} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
    </div>
  );
};
