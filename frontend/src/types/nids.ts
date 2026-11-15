export interface FlowRecord {
  id?: number;
  flow_id: string;
  timestamp?: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: number;
  protocol_name?: string;
  duration_sec: number;
  total_packets: number;
  total_bytes: number;
  predicted_class: string;
  threat_category?: string;
  is_malicious: boolean;
  confidence: number;
  risk_level: 'Low' | 'Medium' | 'High' | 'Critical';
  session_id?: string;
  features?: Record<string, number>;
}

export interface AlertItem {
  id: number;
  alert_id: string;
  timestamp: string;
  source_ip: string;
  destination_ip: string;
  source_port: number;
  destination_port: number;
  protocol: number;
  attack_type: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  confidence: number;
  anomaly_score: number;
  model_name: string;
  occurrence_count: number;
  evidence: {
    flow_features?: Record<string, number>;
    detection_probabilities?: Record<string, number>;
    is_anomaly?: boolean;
    anomaly_score?: number;
  };
}

export interface DashboardOverview {
  total_packets: number;
  total_flows: number;
  benign_count: number;
  malicious_count: number;
  active_alerts: number;
  detection_rate_pct: number;
  attack_distribution: Record<string, number>;
  protocol_distribution: Record<string, number>;
  recent_detections: FlowRecord[];
  traffic_history: Array<{
    time: string;
    total_flows: number;
    benign_flows: number;
    malicious_flows: number;
    total_bytes: number;
  }>;
}

export interface NetworkInterface {
  id: string;
  name: string;
  is_default: boolean;
  is_loopback: boolean;
  status: string;
}

export interface CaptureStatus {
  is_running: boolean;
  interface: string | null;
  uptime_seconds: number;
  packets_captured: number;
  active_flows: number;
  completed_flows: number;
  packets_per_sec: number;
}

export interface ModelMetrics {
  accuracy: number;
  precision_macro: number;
  recall_macro: number;
  f1_macro: number;
  precision_weighted: number;
  recall_weighted: number;
  f1_weighted: number;
  false_positive_rate: number;
  roc_auc: number | null;
  confusion_matrix: {
    matrix: number[][];
    classes: string[];
  };
  per_class: Record<string, {
    precision: number;
    recall: number;
    f1_score: number;
    support: number;
  }>;
}

export interface ModelInfo {
  active_model: string;
  available_models: string[];
  dataset: string;
  total_training_samples: number;
  features_count: number;
  classes: string[];
  metadata: {
    champion_model: string;
    timestamp: string;
    train_samples: number;
    val_samples: number;
    test_samples: number;
    models: Record<string, {
      name: string;
      type: string;
      hyperparameters: Record<string, any>;
      metrics: ModelMetrics;
      feature_importances?: Record<string, number>;
    }>;
  };
}

export interface SamplePcap {
  filename: string;
  size_bytes: number;
  description: string;
}
