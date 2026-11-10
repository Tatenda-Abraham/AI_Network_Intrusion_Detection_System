"""
AI-NIDS Feature Engineering & Validation Pipeline
Chinhoyi University of Technology - Group 5
Defines the live-computable flow feature set shared between raw network packet
aggregations (Wireshark/TShark) and preloaded CICFlowMeter datasets (cic.csv).
"""

import numpy as np
import pandas as pd
import time
from typing import Dict, List, Tuple, Any

# 34 Live-Computable features shared between cic.csv and bidirectional Wireshark flow aggregations
LIVE_FEATURE_NAMES = [
    "Dst Port",
    "Protocol",
    "Flow Duration",
    "Tot Fwd Pkts",
    "Tot Bwd Pkts",
    "TotLen Fwd Pkts",
    "TotLen Bwd Pkts",
    "Fwd Pkt Len Max",
    "Fwd Pkt Len Min",
    "Fwd Pkt Len Mean",
    "Fwd Pkt Len Std",
    "Bwd Pkt Len Max",
    "Bwd Pkt Len Min",
    "Bwd Pkt Len Mean",
    "Bwd Pkt Len Std",
    "Flow Byts/s",
    "Flow Pkts/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Mean",
    "Bwd IAT Mean",
    "Pkt Len Min",
    "Pkt Len Max",
    "Pkt Len Mean",
    "Pkt Len Std",
    "FIN Flag Cnt",
    "SYN Flag Cnt",
    "RST Flag Cnt",
    "PSH Flag Cnt",
    "ACK Flag Cnt",
    "Down/Up Ratio",
    "Pkt Size Avg"
]

FEATURE_RANGES = {
    "Dst Port": (0, 65535),
    "Protocol": (0, 255),
    "Flow Duration": (0, 1e9),
    "Tot Fwd Pkts": (0, 1e8),
    "Tot Bwd Pkts": (0, 1e8),
    "TotLen Fwd Pkts": (0, 1e11),
    "TotLen Bwd Pkts": (0, 1e11),
    "SYN Flag Cnt": (0, 1e7),
    "ACK Flag Cnt": (0, 1e7),
    "FIN Flag Cnt": (0, 1e7),
    "RST Flag Cnt": (0, 1e7),
    "Down/Up Ratio": (0, 1e6)
}


class FeatureValidationError(Exception):
    """Custom exception raised when flow feature validation fails."""
    pass


class FeaturePipeline:
    def __init__(self, feature_list: List[str] = None):
        self.feature_list = feature_list or LIVE_FEATURE_NAMES

    def validate_features(self, feature_dict: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Validates feature presence, numeric types, and logical boundaries.
        Supports TD04 (missing feature), TD05 (invalid type), TD06 (out-of-range).
        """
        for feature in self.feature_list:
            if feature not in feature_dict or feature_dict[feature] is None:
                return False, f"Missing required feature: '{feature}'"

            val = feature_dict[feature]
            if not isinstance(val, (int, float, np.integer, np.floating)):
                try:
                    val = float(val)
                except (ValueError, TypeError):
                    return False, f"Invalid data type for feature '{feature}': expected numeric, got {type(val).__name__}"

            if np.isnan(val) or np.isinf(val):
                return False, f"Feature '{feature}' contains invalid NaN or Inf value"

            if feature in FEATURE_RANGES:
                min_val, max_val = FEATURE_RANGES[feature]
                if val < min_val or val > max_val:
                    return False, f"Feature '{feature}' value {val} out of permitted range [{min_val}, {max_val}]"

        return True, "Valid"

    def prepare_vector(self, feature_dict: Dict[str, Any]) -> np.ndarray:
        """Converts a feature dict into a 1D numpy array ordered by self.feature_list."""
        is_valid, reason = self.validate_features(feature_dict)
        if not is_valid:
            raise FeatureValidationError(reason)

        return np.array([float(feature_dict[col]) for col in self.feature_list], dtype=np.float32)

    def clean_dataframe(self, df: pd.DataFrame) -> Tuple[pd.DataFrame, float]:
        """
        Cleans and sanitizes a pandas DataFrame containing flow features.
        Replaces inf/-inf with NaN, drops missing values, and measures preprocessing latency.
        """
        t0 = time.time()
        # Ensure required features exist
        available_cols = [col for col in self.feature_list if col in df.columns]
        cleaned = df[available_cols].copy()

        # Handle infinite and null values
        cleaned.replace([np.inf, -np.inf], np.nan, inplace=True)
        cleaned.fillna(0.0, inplace=True)

        for col in available_cols:
            cleaned[col] = pd.to_numeric(cleaned[col], errors='coerce').fillna(0.0)

        latency_ms = (time.time() - t0) * 1000.0
        return cleaned, latency_ms
