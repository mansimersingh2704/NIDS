# AI-NIDS Machine Learning & Detection Methodology

## 1. Dataset Selection & Authenticity

Rather than relying on fabricated synthetic records or obsolete datasets (such as KDD99), AI-NIDS is trained directly on gold-standard **CIC-IDS2017** benchmark partitions published by the Canadian Institute for Cybersecurity:
- `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` (158,930 PortScan attacks, 127,537 Benign flows)
- `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` (128,027 DDoS attacks, 97,718 Benign flows)

A curated, balanced training corpus of **75,927 validated network flows** was extracted across the three core security categories:
- **BENIGN**: 29,182 flows (Normal HTTP, HTTPS, DNS, NTP sessions)
- **DDoS**: 24,999 flows (High-rate distributed HTTP LOIC/Slowloris attacks)
- **PortScan**: 21,746 flows (Nmap multi-service probes and sweep scans)

## 2. Feature Compatibility & Contract Investigation

A major failure point in academic NIDS implementations is "feature schema divergence," where an offline model is trained on bidirectional features (e.g., backward inter-arrival times or merged segment lengths) that a real-time live packet sniffer cannot compute without maintaining complex reverse-connection state tables.

AI-NIDS resolves this by establishing a **Directional Feature Contract**:
Every feature in the 22-dimensional feature vector is strictly unidirectional and computed identically in both offline PCAP processing and live streaming capture:

| Feature Name | Type | Description | Unit |
| :--- | :--- | :--- | :--- |
| `destination_port` | Integer | Target transport port (key indicator of probed services) | Port # |
| `flow_duration` | Float | Microseconds elapsed between first and last packet | Microseconds |
| `total_packets` | Integer | Total directional packet count in flow | Packets |
| `total_bytes` | Integer | Total directional payload length | Bytes |
| `packet_len_min` | Float | Minimum packet length observed in flow | Bytes |
| `packet_len_max` | Float | Maximum packet length observed in flow | Bytes |
| `packet_len_mean` | Float | Arithmetic mean packet length | Bytes |
| `packet_len_std` | Float | Standard deviation of packet lengths | Bytes |
| `packet_len_var` | Float | Variance of packet lengths | Bytes$^2$ |
| `flow_bytes_per_sec`| Float | Directional throughput rate | Bytes / sec |
| `flow_packets_per_sec`| Float | Directional packet transmission frequency | Packets / sec |
| `flow_iat_mean` | Float | Mean inter-arrival time between consecutive packets | Microseconds |
| `flow_iat_std` | Float | Standard deviation of packet inter-arrival times | Microseconds |
| `flow_iat_max` | Float | Maximum inter-arrival gap | Microseconds |
| `flow_iat_min` | Float | Minimum inter-arrival gap | Microseconds |
| `fin_flag_count` | Integer | Count of packets with TCP FIN flag | Count |
| `syn_flag_count` | Integer | Count of packets with TCP SYN flag | Count |
| `rst_flag_count` | Integer | Count of packets with TCP RST flag | Count |
| `psh_flag_count` | Integer | Count of packets with TCP PSH flag | Count |
| `ack_flag_count` | Integer | Count of packets with TCP ACK flag | Count |
| `urg_flag_count` | Integer | Count of packets with TCP URG flag | Count |
| `avg_packet_size` | Float | Mean packet segment size | Bytes |

## 3. Preprocessing & Prevention of Data Leakage

1. **Infinite Value Handling**: Division-by-zero occurrences (e.g. `flow_bytes_per_sec` when `flow_duration == 0`) are converted to `NaN` and replaced with column medians.
2. **Duplicate Removal**: Duplicate rows from identical flow captures are stripped (4,073 duplicates eliminated).
3. **Imputation & Scaling**: A `StandardScaler` is fitted **strictly on the 70% training split**. The validation (15%) and test (15%) splits are transformed using the training parameters, preventing data leakage.
4. **Stratified Splitting**: Train (53,148 flows), Validation (11,389 flows), and Test (11,390 flows) maintain identical class proportions (`BENIGN`: 38.4%, `DDoS`: 32.9%, `PortScan`: 28.7%).

## 4. Empirical Evaluation Results

The models were evaluated on the held-out test partition (11,390 samples):

| Evaluation Metric | Random Forest (Champion) | XGBoost Classifier |
| :--- | :--- | :--- |
| **Accuracy** | **99.97%** | **99.96%** |
| **Precision (Macro)** | **99.98%** | **99.96%** |
| **Recall (Macro)** | **99.97%** | **99.96%** |
| **F1-Score (Macro)** | **99.98%** | **99.97%** |
| **False Positive Rate (FPR)** | **0.05%** | **0.07%** |
| **Inference Latency** | **~0.12 ms / flow** | **~0.18 ms / flow** |

### Per-Class Test Performance (Random Forest)
- **BENIGN**: Precision = 0.9995, Recall = 1.0000, F1-Score = 0.9998 (Support: 4,377)
- **DDoS**: Precision = 1.0000, Recall = 0.9997, F1-Score = 0.9999 (Support: 3,750)
- **PortScan**: Precision = 1.0000, Recall = 0.9994, F1-Score = 0.9997 (Support: 3,263)

### Unsupervised Anomaly Detection (Isolation Forest)
An `IsolationForest` was fitted on benign baseline flows with $3\%$ contamination. When evaluated against the test split, it isolated abnormal outliers without requiring labeled attack supervision, providing complementary defense against novel attack vectors.

## 5. Risk Level Assignment Rationale

A critical security principle is that **model confidence does not equal threat severity**. A classifier may be 99% confident that an incoming packet is a single low-impact port scan probe, while a slow DDoS flood may have 75% confidence but poses critical risk to server availability.

AI-NIDS decouples probability from severity:
- **Critical**: Assigned to confirmed high-impact volumetric attacks (DDoS) threatening service availability.
- **High**: Assigned to active multi-port reconnaissance (PortScan) targeting sensitive enterprise infrastructure.
- **Medium**: Assigned to statistical zero-day outliers flagged by Isolation Forest or suspicious multi-packet sweeps.
- **Low**: Assigned to standard benign traffic and low-frequency administrative transactions.

## 6. Alert Deduplication Mechanism

In high-throughput attacks (such as port sweeps or SYN floods), thousands of packets can trigger alerts every second, causing "alert fatigue" and exhausting SOC analyst capacity.

AI-NIDS implements a sliding temporal deduplication window ($30$ seconds by default):
$$\text{DedupKey} = (\text{src\_ip}, \text{dst\_ip}, \text{attack\_type})$$
When subsequent flows match an active `DedupKey` within the temporal window, the system:
1. Increments `occurrence_count` on the existing alert in SQLite.
2. Updates `last_seen` timestamp.
3. Appends the newest flow evidence.
4. Suppresses redundant notifications on the SOC dashboard.
