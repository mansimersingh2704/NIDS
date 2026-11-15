# AI-NIDS System Architecture

## 1. Architectural Overview

AI-NIDS is an enterprise-grade, passive Network Intrusion Detection System built for Security Operations Center (SOC) environments. The system ingests network packets either in real-time from physical/virtual network adapters or offline from PCAP captures, extracts directional flow metadata, performs multi-class supervised classification and unsupervised anomaly detection, and streams deduplicated alerts to a modern SOC dashboard.

```
+-----------------------------------------------------------------------------------+
|                            PASSIVE TRAFFIC SOURCE                                 |
|   Live Raw Interface (Promiscuous)             Offline PCAP / PCAPNG Files        |
+--------------------------+------------------------------------+-------------------+
                           |                                    |
                           v                                    v
+-----------------------------------------------------------------------------------+
|                        PASSIVE TRAFFIC INGESTION ENGINE                           |
|       - Scapy AsyncSniffer / PcapReader                                           |
|       - Strict Passive Constraint (Zero packet injection, modification, or RST)   |
|       - Protocol Decoding: IPv4, IPv6, TCP, UDP, ICMP                             |
+----------------------------------+------------------------------------------------+
                                   |
                                   v
+-----------------------------------------------------------------------------------+
|                       DIRECTIONAL FLOW MANAGER (FlowManager)                      |
|       - Directional 5-Tuple Key: (src_ip, dst_ip, src_port, dst_port, protocol)   |
|       - Strict Directional Isolation: A->B and B->A are NEVER merged              |
|       - TCP State Machine: Instant termination on FIN / RST flags                 |
|       - Temporal Sweeper: Idle Timeout (15s) and Active Timeout (60s)             |
+----------------------------------+------------------------------------------------+
                                   | Completed DirectionalFlow
                                   v
+-----------------------------------------------------------------------------------+
|                       FEATURE EXTRACTION (flow_features.py)                       |
|       - Directional wire and payload lengths: min, max, mean, std, variance       |
|       - Temporal dynamics: flow_duration, packets/sec, bytes/sec                  |
|       - Inter-Arrival Times (IAT): mean, std, max, min (in microseconds)          |
|       - TCP Flag Vectors: FIN, SYN, RST, PSH, ACK, URG counts                     |
+----------------------------------+------------------------------------------------+
                                   | Feature Vector (22 standard features)
                                   v
+-----------------------------------------------------------------------------------+
|                       MACHINE LEARNING INFERENCE ENGINE                           |
|       - Preprocessor: Median Imputation + StandardScaler (leakage-free)           |
|       - Champion Classifier: Random Forest & XGBoost Multi-Class                  |
|       - Anomaly Detection: Isolation Forest baseline for zero-day outliers        |
|       - Risk Calibrator: Confidence != Severity (maps class to SOC Risk Level)    |
+----------------------------------+------------------------------------------------+
                                   | Detection Result & Probabilities
                                   v
+-----------------------------------------------------------------------------------+
|                      DETECTION ENGINE & ALERT MANAGER                             |
|       - SQLite Database Persistence (network_flows & alerts)                      |
|       - Sliding-Window Alert Deduplication (src_ip, dst_ip, attack_type)          |
|       - High-Performance Bulk Batch Insertion for PCAP replay                     |
|       - Rolling In-Memory SOC Telemetry (Traffic timelines, Protocol distributions)|
+----------------------------------+------------------------------------------------+
                                   |
                  +----------------+----------------+
                  |                                 |
                  v                                 v
+----------------------------------+ +----------------------------------------------+
|        REST API (FastAPI)        | |           WEBSOCKET DISPATCHER               |
|  - /api/health                   | |  - /api/ws                                   |
|  - /api/dashboard/overview       | |  - Real-time Flow Broadcasting               |
|  - /api/alerts & /api/detections | |  - Live Alert Notifications                  |
|  - /api/pcap/analyze             | +----------------------+-----------------------+
|  - /api/models/metrics           |                        |
+-----------------+----------------+                        |
                  |                                         |
                  +--------------------+--------------------+
                                       |
                                       v
+-----------------------------------------------------------------------------------+
|                         REACT SOC DASHBOARD (Frontend)                            |
|       - Page 1: Overview Dashboard (KPIs, Recharts Timelines, Pie, Bar)           |
|       - Page 2: Live Monitoring (Interface Selector, Start/Stop, Stream)          |
|       - Page 3: PCAP Analysis (Drag-and-Drop, Sample Library, Breakdown)          |
|       - Page 4: Alert Management (Filters, Search, Forensic Modal)                |
|       - Page 5: Model Performance (Confusion Matrix, Feature Importances, Switch)  |
|       - Page 6: Security Reports (Executive Briefing, CSV Exports)                |
+-----------------------------------------------------------------------------------+
```

## 2. Key Architectural Tenets

### 2.1 Strictly Passive Surveillance
In production security environments, an IDS must never perturb target networks. AI-NIDS binds exclusively in read-only tap mode:
- No raw packet transmission or probe emission.
- No automated IP firewall blocking or connection teardowns (avoiding self-inflicted denial of service).
- Safe error handling for permission bounds (Windows Npcap and Linux `CAP_NET_RAW`).

### 2.2 Directional Flow Tuple Isolation
Standard netflow aggregators often blend client-to-server and server-to-client packets into a single bidirectional flow. This obscures attack asymmetries (such as asymmetric SYN flood floods or unilateral port probes). 
AI-NIDS identifies flows directionally:
$$\text{FlowKey} = (\text{src\_ip}, \text{dst\_ip}, \text{src\_port}, \text{dst\_port}, \text{protocol})$$
Traffic from $A \to B$ and $B \to A$ remain isolated, ensuring forward packet counters and flag metrics are pristine.

### 2.3 Decoupled Modular Design
Every subsystem (Ingest, Flow Tracking, ML Preprocessing, Model Registry, Alerting, API, WebSocket, and UI) resides in separate, testable modules with well-defined interfaces and zero circular dependencies.
