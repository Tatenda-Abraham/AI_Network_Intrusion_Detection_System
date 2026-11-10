"""
AI-NIDS Machine Learning Service
Chinhoyi University of Technology - Group 5
Handles model loading, inference, confidence scoring, algorithm selection
(Random Forest vs Decision Tree), and feature attribution.
"""

import os
import json
import time
import joblib
import numpy as np
from typing import Dict, List, Tuple, Any, Optional

from backend.services.feature_pipeline import FeaturePipeline, LIVE_FEATURE_NAMES

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MODELS_DIR = os.path.join(BASE_DIR, "models")
CONFIG_DIR = os.path.join(BASE_DIR, "config")
LABEL_MAP_PATH = os.path.join(CONFIG_DIR, "label_map.json")


class MLService:
    def __init__(self, model_version: str = "rf_v1"):
        self.model_version = model_version
        self.primary_model_path = os.path.join(MODELS_DIR, "rf_v1.joblib")
        self.alt_model_path = os.path.join(MODELS_DIR, "dt_v1.joblib")
        self.meta_path = os.path.join(MODELS_DIR, "metadata.json")

        self.current_model = None
        self.active_algorithm = "Random Forest"
        self.metadata = {}
        self.label_map = {}
        self.pipeline = FeaturePipeline()

        self._load_label_map()
        self.load_model()

    def _load_label_map(self):
        if os.path.exists(LABEL_MAP_PATH):
            with open(LABEL_MAP_PATH, "r") as f:
                self.label_map = json.load(f)
        else:
            self.label_map = {"mappings": {}}

    def load_model(self, use_decision_tree: bool = False) -> bool:
        """Loads or switches between Random Forest and Decision Tree."""
        target_path = self.alt_model_path if use_decision_tree else self.primary_model_path
        self.active_algorithm = "Decision Tree" if use_decision_tree else "Random Forest"

        if os.path.exists(target_path):
            self.current_model = joblib.load(target_path)
            if os.path.exists(self.meta_path):
                with open(self.meta_path, "r") as f:
                    self.metadata = json.load(f)
            return True
        return False

    def predict_flow(self, flow_features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Runs ML prediction on a single flow feature dictionary.
        Returns predicted raw label, mapped attack category, 3-tier ml_class,
        confidence score, and inference latency.
        """
        if self.current_model is None:
            if not self.load_model():
                raise RuntimeError("ML model is not loaded and no trained model was found in models/.")

        t0 = time.time()
        vector = self.pipeline.prepare_vector(flow_features).reshape(1, -1)

        raw_pred = self.current_model.predict(vector)[0]
        proba = self.current_model.predict_proba(vector)[0]
        max_idx = np.argmax(proba)
        confidence = float(proba[max_idx])

        # Map raw label to CUT project categories and 3-tier ML class
        mappings = self.label_map.get("mappings", {})
        map_info = mappings.get(str(raw_pred).strip(), {})

        attack_type = map_info.get("category", "Normal" if raw_pred == "Benign" else "Brute Force")
        ml_class = map_info.get("ml_class", "Normal" if attack_type == "Normal" else "Potential Attack")

        latency_ms = (time.time() - t0) * 1000.0

        return {
            "raw_label": str(raw_pred),
            "attack_type": attack_type,
            "ml_class": ml_class,
            "confidence_score": round(confidence, 4),
            "inference_latency_ms": round(latency_ms, 3),
            "algorithm": self.active_algorithm,
            "model_version": self.metadata.get("model_version", "rf_v1")
        }

    def predict_batch(self, features_df) -> Tuple[List[Dict[str, Any]], float]:
        """Runs fast vectorized batch prediction on a pandas DataFrame or 2D array."""
        if self.current_model is None:
            if not self.load_model():
                raise RuntimeError("ML model not loaded.")

        t0 = time.time()
        preds = self.current_model.predict(features_df)
        probas = self.current_model.predict_proba(features_df)
        elapsed_ms = (time.time() - t0) * 1000.0

        mappings = self.label_map.get("mappings", {})
        results = []
        for raw_pred, proba in zip(preds, probas):
            conf = float(np.max(proba))
            map_info = mappings.get(str(raw_pred).strip(), {})
            attack_type = map_info.get("category", "Normal" if raw_pred == "Benign" else "Brute Force")
            ml_class = map_info.get("ml_class", "Normal" if attack_type == "Normal" else "Potential Attack")

            results.append({
                "raw_label": str(raw_pred),
                "attack_type": attack_type,
                "ml_class": ml_class,
                "confidence_score": round(conf, 4)
            })

        return results, elapsed_ms

    def get_metrics(self) -> Dict[str, Any]:
        """Returns loaded model metrics, evaluation matrix, and target benchmarking."""
        if not self.metadata and os.path.exists(self.meta_path):
            with open(self.meta_path, "r") as f:
                self.metadata = json.load(f)
        return self.metadata
