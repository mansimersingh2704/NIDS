"""
Dataset Preparation Script for AI-NIDS.
Loads real CIC-IDS2017 benchmark CSV partitions (Friday PortScan and DDoS),
extracts directional network flow features, cleans malformed/infinite values,
removes duplicate records, balances classes, and saves the cleaned dataset.
"""

import json
import logging
import os
from pathlib import Path
import numpy as np
import pandas as pd

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

FEATURE_MAPPING = {
    "Destination Port": "destination_port",
    "Flow Duration": "flow_duration",
    "Total Fwd Packets": "total_packets",
    "Total Length of Fwd Packets": "total_bytes",
    "Fwd Packet Length Min": "packet_len_min",
    "Fwd Packet Length Max": "packet_len_max",
    "Fwd Packet Length Mean": "packet_len_mean",
    "Fwd Packet Length Std": "packet_len_std",
    "Packet Length Variance": "packet_len_var",
    "Flow Bytes/s": "flow_bytes_per_sec",
    "Flow Packets/s": "flow_packets_per_sec",
    "Flow IAT Mean": "flow_iat_mean",
    "Flow IAT Std": "flow_iat_std",
    "Flow IAT Max": "flow_iat_max",
    "Flow IAT Min": "flow_iat_min",
    "FIN Flag Count": "fin_flag_count",
    "SYN Flag Count": "syn_flag_count",
    "RST Flag Count": "rst_flag_count",
    "PSH Flag Count": "psh_flag_count",
    "ACK Flag Count": "ack_flag_count",
    "URG Flag Count": "urg_flag_count",
    "Average Packet Size": "avg_packet_size",
    "Label": "label"
}

FEATURE_COLUMNS = [v for k, v in FEATURE_MAPPING.items() if k != "Label"]

def prepare_dataset(
    raw_dir: Path = Path("data/raw"),
    processed_dir: Path = Path("data/processed"),
    benign_samples: int = 30000,
    portscan_samples: int = 25000,
    ddos_samples: int = 25000,
    random_seed: int = 42
) -> pd.DataFrame:
    processed_dir.mkdir(parents=True, exist_ok=True)

    portscan_csv = raw_dir / "Friday-PortScan.csv"
    ddos_csv = raw_dir / "Friday-DDoS.csv"

    if not portscan_csv.exists() or not ddos_csv.exists():
        raise FileNotFoundError(f"Raw CSV files missing in {raw_dir}")

    logger.info("Loading raw CIC-IDS2017 files...")
    df_ps = pd.read_csv(portscan_csv, low_memory=False)
    df_ps.columns = df_ps.columns.str.strip()

    df_ddos = pd.read_csv(ddos_csv, low_memory=False)
    df_ddos.columns = df_ddos.columns.str.strip()

    logger.info("Extracting directional feature subsets...")
    missing_ps = [c for c in FEATURE_MAPPING.keys() if c not in df_ps.columns]
    missing_ddos = [c for c in FEATURE_MAPPING.keys() if c not in df_ddos.columns]
    if missing_ps or missing_ddos:
        raise ValueError(f"Missing columns: {missing_ps or missing_ddos}")

    df_ps_subset = df_ps[list(FEATURE_MAPPING.keys())].rename(columns=FEATURE_MAPPING)
    df_ddos_subset = df_ddos[list(FEATURE_MAPPING.keys())].rename(columns=FEATURE_MAPPING)

    # Standardize labels
    df_ps_subset["label"] = df_ps_subset["label"].str.strip()
    df_ddos_subset["label"] = df_ddos_subset["label"].str.strip()

    logger.info(f"PortScan file labels: {df_ps_subset['label'].value_counts().to_dict()}")
    logger.info(f"DDoS file labels: {df_ddos_subset['label'].value_counts().to_dict()}")

    # Stratified sampling
    ps_attacks = df_ps_subset[df_ps_subset["label"] == "PortScan"].sample(
        n=min(portscan_samples, len(df_ps_subset[df_ps_subset["label"] == "PortScan"])),
        random_state=random_seed
    )
    ps_benign = df_ps_subset[df_ps_subset["label"] == "BENIGN"].sample(
        n=min(benign_samples // 2, len(df_ps_subset[df_ps_subset["label"] == "BENIGN"])),
        random_state=random_seed
    )

    ddos_attacks = df_ddos_subset[df_ddos_subset["label"] == "DDoS"].sample(
        n=min(ddos_samples, len(df_ddos_subset[df_ddos_subset["label"] == "DDoS"])),
        random_state=random_seed
    )
    ddos_benign = df_ddos_subset[df_ddos_subset["label"] == "BENIGN"].sample(
        n=min(benign_samples // 2, len(df_ddos_subset[df_ddos_subset["label"] == "BENIGN"])),
        random_state=random_seed
    )

    combined = pd.concat([ps_benign, ddos_benign, ps_attacks, ddos_attacks], ignore_index=True)
    logger.info(f"Combined raw samples: {len(combined)}")

    # Clean data
    # 1. Replace infinite with NaN
    combined.replace([np.inf, -np.inf], np.nan, inplace=True)

    # 2. Drop duplicates
    initial_len = len(combined)
    combined.drop_duplicates(inplace=True)
    logger.info(f"Removed {initial_len - len(combined)} duplicate rows.")

    # 3. Handle negative flow duration or values
    for col in FEATURE_COLUMNS:
        combined[col] = pd.to_numeric(combined[col], errors="coerce")
        # Flow duration and stats cannot be negative
        combined[col] = combined[col].clip(lower=0.0)

    # 4. Impute any remaining NaNs with column medians
    medians = combined[FEATURE_COLUMNS].median().to_dict()
    combined.fillna(medians, inplace=True)

    # Add binary label
    combined["is_malicious"] = (combined["label"] != "BENIGN").astype(int)

    logger.info(f"Final cleaned dataset shape: {combined.shape}")
    logger.info(f"Label distribution:\n{combined['label'].value_counts()}")
    logger.info(f"Binary distribution:\n{combined['is_malicious'].value_counts()}")

    # Save processed CSV
    out_csv = processed_dir / "cicids2017_cleaned.csv"
    combined.to_csv(out_csv, index=False)
    logger.info(f"Saved cleaned dataset to {out_csv}")

    # Save feature metadata & schema
    schema = {
        "dataset_name": "CIC-IDS2017 (Curated Directional Flow Subset)",
        "source": "Canadian Institute for Cybersecurity (ISCX Friday captures)",
        "total_records": len(combined),
        "feature_columns": FEATURE_COLUMNS,
        "n_features": len(FEATURE_COLUMNS),
        "classes": sorted(combined["label"].unique().tolist()),
        "binary_mapping": {"BENIGN": 0, "PortScan": 1, "DDoS": 1},
        "medians": medians
    }

    schema_file = processed_dir / "feature_schema.json"
    with open(schema_file, "w") as f:
        json.dump(schema, f, indent=2)
    logger.info(f"Saved feature schema to {schema_file}")

    return combined

if __name__ == "__main__":
    prepare_dataset()
