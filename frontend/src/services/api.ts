import axios from 'axios';
import {
  AlertItem,
  CaptureStatus,
  DashboardOverview,
  FlowRecord,
  ModelInfo,
  NetworkInterface,
  SamplePcap,
} from '../types/nids';

const apiClient = axios.create({
  baseURL: '/api',
  timeout: 45000,
});

export const api = {
  // Health
  getHealth: () => apiClient.get('/health'),

  // Interfaces & Live Capture
  getInterfaces: () => apiClient.get<NetworkInterface[]>('/interfaces'),
  getCaptureStatus: () => apiClient.get<CaptureStatus>('/capture/status'),
  startCapture: (iface?: string) => apiClient.post('/capture/start', { interface: iface }),
  stopCapture: () => apiClient.post('/capture/stop'),

  // Dashboard
  getDashboardOverview: () => apiClient.get<DashboardOverview>('/dashboard/overview'),
  getTrafficHistory: () => apiClient.get('/dashboard/traffic'),
  getAttackDistribution: () => apiClient.get('/dashboard/attacks'),

  // Alerts
  getAlerts: (params: {
    page?: number;
    limit?: number;
    severity?: string;
    attack_type?: string;
    ip?: string;
  }) => apiClient.get<{ total: number; page: number; limit: number; alerts: AlertItem[] }>('/alerts', { params }),
  getAlertById: (alertId: string) => apiClient.get<AlertItem>(`/alerts/${alertId}`),

  // Detections
  getDetections: (params: {
    page?: number;
    limit?: number;
    is_malicious?: boolean;
    predicted_class?: string;
    ip?: string;
  }) => apiClient.get<{ total: number; page: number; limit: number; detections: FlowRecord[] }>('/detections', { params }),

  // Models
  getModelInfo: () => apiClient.get<ModelInfo>('/models/info'),
  getModelMetrics: () => apiClient.get('/models/metrics'),
  switchModel: (modelName: string) => apiClient.post('/models/switch', { model_name: modelName }),

  // PCAP Analysis
  uploadPcap: (file: File) => {
    const formData = new FormData();
    formData.append('file', file);
    return apiClient.post('/pcap/upload', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
  },
  analyzePcap: (filename: string, maxPackets?: number) =>
    apiClient.post('/pcap/analyze', { filename, max_packets: maxPackets }),
  getSamplePcaps: () => apiClient.get<{ samples: SamplePcap[] }>('/pcap/samples'),

  // Reports
  getReportSummary: () => apiClient.get('/reports/summary'),
  getExportUrl: (type: 'flows' | 'alerts') => `/api/reports/export?export_type=${type}`,
};
