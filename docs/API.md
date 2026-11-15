# AI-NIDS RESTful API Documentation

Base URL: `http://localhost:8000/api`

Interactive Swagger UI: `http://localhost:8000/docs`

---

## 1. System Health & Environment

### `GET /api/health`
Returns system status, loaded machine learning models, active champion model, and sniffer state.

**Response (200 OK):**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "active_model": "random_forest",
  "models_loaded": ["random_forest", "xgboost"],
  "capture_running": false,
  "active_interface": null,
  "timestamp": "2026-11-15T10:33:49.003238+00:00"
}
```

---

## 2. Network Interfaces & Passive Monitoring

### `GET /api/interfaces`
Enumerates available host network capture adapters.

**Response (200 OK):**
```json
[
  {
    "id": "\\Device\\NPF_{48CE3C87-0206-4EBB-88C7-F276DE4091FE}",
    "name": "Wi-Fi Adapter",
    "is_default": true,
    "is_loopback": false,
    "status": "ready"
  }
]
```

### `POST /api/capture/start`
Starts passive packet capture on the designated adapter.

**Request Body:**
```json
{
  "interface": "\\Device\\NPF_{48CE3C87-0206-4EBB-88C7-F276DE4091FE}"
}
```

### `POST /api/capture/stop`
Stops active passive monitoring and flushes any pending directional flows.

### `GET /api/capture/status`
Returns real-time packet sniffer telemetry, active flow count, and throughput.

---

## 3. PCAP Ingestion & Offline Security Analysis

### `POST /api/pcap/upload`
Uploads a `.pcap` or `.pcapng` file (Multipart Form, max 50MB).

### `POST /api/pcap/analyze`
Extracts directional flows, executes inference, and stores results in the database.

**Request Body:**
```json
{
  "filename": "port_scan_attack.pcap",
  "max_packets": 5000
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "filename": "port_scan_attack.pcap",
  "packets_count": 70,
  "flows_count": 28,
  "benign_count": 14,
  "malicious_count": 14,
  "attacks_detected": {
    "PortScan": 14
  },
  "processing_time_sec": 0.086,
  "alerts_generated": 1,
  "detections": [...]
}
```

### `GET /api/pcap/samples`
Lists built-in test captures (`benign_traffic.pcap`, `port_scan_attack.pcap`, `ddos_attack.pcap`, `mixed_traffic.pcap`).

---

## 4. SOC Dashboard Analytics

### `GET /api/dashboard/overview`
Retrieves aggregate KPIs, attack category distribution, protocol breakdown, and recent detections.

### `GET /api/dashboard/traffic`
Returns time-series flow and volume history for traffic activity line charts.

### `GET /api/dashboard/attacks`
Returns multi-class threat distribution breakdown.

---

## 5. Security Alerts

### `GET /api/alerts`
Paginated alerts list with filtering.

**Query Parameters:**
- `page` (int, default: 1)
- `limit` (int, default: 20)
- `severity` (string: `Critical`, `High`, `Medium`, `Low`)
- `attack_type` (string)
- `ip` (string: matches source or destination IP)

### `GET /api/alerts/{alert_id}`
Returns full alert detail, forensic evidence vector, and class probabilities.

---

## 6. Flow Detections History

### `GET /api/detections`
Paginated network flow records.

**Query Parameters:**
- `page` (int, default: 1)
- `limit` (int, default: 25)
- `is_malicious` (bool)
- `predicted_class` (string)
- `ip` (string)

---

## 7. Machine Learning Model Management

### `GET /api/models/info`
Returns active champion model, available models, training dataset statistics, and feature schemas.

### `GET /api/models/metrics`
Returns empirical validation metrics (Accuracy, Precision, Recall, F1, Confusion Matrix, FPR, Feature Importances).

### `POST /api/models/switch`
Dynamically switches the active inference model without restarting the server.

**Request Body:**
```json
{
  "model_name": "xgboost"
}
```

---

## 8. Reports & Audits

### `GET /api/reports/summary`
Returns executive summary metrics suitable for SOC management briefings.

### `GET /api/reports/export?export_type={flows|alerts}`
Streams downloadable CSV export of flow detections or security alerts.

---

## 9. Real-Time WebSocket Live Feed

### `WebSocket /api/ws`
Streams live flow detections and alert updates:
- Message format: `{"type": "flow" | "alert" | "init", "data": {...}}`
- Keepalive ping/pong supported.
