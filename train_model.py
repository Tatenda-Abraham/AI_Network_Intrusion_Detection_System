"""
AI-NIDS Model Training and Evaluation Pipeline
Chinhoyi University of Technology (CUT)
School of Engineering Sciences and Technology
Department of ICT and Electronics (BSc Hons IT, Group 5)

Performs:
1. Label inspection and distribution audit
2. Stratified chunk-based sampling from data/cic.csv
3. Feature sanitization (handling NaN/Inf, type casting)
4. Stratified 80/20 Train/Test split
5. Training Random Forest (primary) & Decision Tree (selectable alternative)
6. Comprehensive evaluation: Accuracy, Precision, Recall, F1, FPR, Confusion Matrix
7. Target benchmarking against project requirements (Accuracy >= 95%, FPR < 3%)
8. Model persistence (models/rf_v1.joblib) and metadata JSON storage
"""

import os
import json
import time
import joblib
import numpy as np
import pandas as pd
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, precision_recall_fscore_support, confusion_matrix

from backend.services.feature_pipeline import LIVE_FEATURE_NAMES, FeaturePipeline

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(BASE_DIR, "data", "cic.csv")
MODELS_DIR = os.path.join(BASE_DIR, "models")
CONFIG_DIR = os.path.join(BASE_DIR, "config")
LABEL_MAP_PATH = os.path.join(CONFIG_DIR, "label_map.json")

os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(CONFIG_DIR, exist_ok=True)


def load_label_map():
    if os.path.exists(LABEL_MAP_PATH):
        with open(LABEL_MAP_PATH, "r") as f:
            return json.load(f)
    return {"mappings": {}, "categories": [], "ml_classes": []}


def inspect_dataset_labels(filepath: str):
    print(f"[*] Inspecting labels in dataset: {filepath}")
    t0 = time.time()
    label_counts = {}
    for chunk in pd.read_csv(filepath, usecols=["Label"], chunksize=100000):
        vc = chunk["Label"].value_counts().to_dict()
        for k, v in vc.items():
            label_counts[k] = label_counts.get(k, 0) + v

    elapsed = time.time() - t0
    print(f"[+] Label inspection complete in {elapsed:.2f}s:")
    for lbl, count in label_counts.items():
        print(f"    - {lbl}: {count:,} samples")
    return label_counts


def load_stratified_dataset(filepath: str, max_per_class: int = 15000):
    print(f"\n[*] Extracting stratified sample (up to {max_per_class} per class)...")
    cols_to_load = LIVE_FEATURE_NAMES + ["Label"]
    pipeline = FeaturePipeline()

    class_buffers = {}
    total_loaded = 0

    for chunk in pd.read_csv(filepath, usecols=cols_to_load, chunksize=100000):
        for label, group in chunk.groupby("Label"):
            if label not in class_buffers:
                class_buffers[label] = []

            current_count = sum(len(b) for b in class_buffers[label])
            needed = max_per_class - current_count
            if needed > 0:
                take_n = min(len(group), needed)
                class_buffers[label].append(group.sample(n=take_n, random_state=42))

        # Check if all classes reached max_per_class
        if all(sum(len(b) for b in buffers) >= max_per_class for buffers in class_buffers.values()):
            break

    sampled_dfs = []
    for lbl, buffers in class_buffers.items():
        if buffers:
            combined = pd.concat(buffers, ignore_index=True)
            sampled_dfs.append(combined)
            print(f"    - {lbl}: {len(combined):,} samples retained")

    full_df = pd.concat(sampled_dfs, ignore_index=True)

    print(f"[*] Sanitizing features and handling NaN/Inf values...")
    cleaned_df, clean_lat = pipeline.clean_dataframe(full_df[LIVE_FEATURE_NAMES])
    cleaned_df["Label"] = full_df["Label"].values
    cleaned_df.dropna(subset=["Label"], inplace=True)
    print(f"[+] Sanitization complete ({clean_lat:.2f} ms). Total valid records: {len(cleaned_df):,}")
    return cleaned_df


def train_and_evaluate():
    print("=" * 70)
    print("CHINHOYI UNIVERSITY OF TECHNOLOGY - AI-NIDS MODEL TRAINING")
    print("School of Engineering Sciences and Technology | Department of ICT")
    print("=" * 70)

    if not os.path.exists(DATA_PATH):
        raise FileNotFoundError(f"Training dataset not found at {DATA_PATH}. Place cic.csv in data/.")

    # 1. Label Inspection
    label_dist = inspect_dataset_labels(DATA_PATH)
    label_map_data = load_label_map()
    label_mapping = label_map_data.get("mappings", {})

    # 2. Load and clean sample
    df = load_stratified_dataset(DATA_PATH, max_per_class=15000)

    # 3. Prepare feature matrix X and targets y
    X = df[LIVE_FEATURE_NAMES].values
    y_raw = df["Label"].values

    # Determine 3-class ML labels (Normal / Suspicious / Potential Attack)
    y_ml_class = []
    for lbl in y_raw:
        map_info = label_mapping.get(str(lbl).strip(), {})
        y_ml_class.append(map_info.get("ml_class", "Potential Attack" if lbl != "Benign" else "Normal"))
    y_ml_class = np.array(y_ml_class)

    # 80/20 Stratified Split
    X_train, X_test, y_train, y_test, y_raw_train, y_raw_test = train_test_split(
        X, y_ml_class, y_raw, test_size=0.20, random_state=42, stratify=y_raw
    )

    print(f"\n[*] Stratified Split (80/20):")
    print(f"    Training samples:   {len(X_train):,}")
    print(f"    Testing samples:    {len(X_test):,}")

    # 4. Train Primary Model: Random Forest
    print("\n[*] Training Random Forest Classifier (n_estimators=50, max_depth=16)...")
    rf_clf = RandomForestClassifier(n_estimators=50, max_depth=16, random_state=42, n_jobs=-1)
    t0 = time.time()
    rf_clf.fit(X_train, y_raw_train)
    rf_train_time = time.time() - t0
    print(f"[+] Random Forest training finished in {rf_train_time:.2f} seconds.")

    # 5. Train Alternative Model: Decision Tree
    print("[*] Training Selectable Alternative: Decision Tree Classifier...")
    dt_clf = DecisionTreeClassifier(max_depth=16, random_state=42)
    dt_clf.fit(X_train, y_raw_train)
    print(f"[+] Decision Tree training complete.")

    # 6. Evaluate Random Forest
    t_eval_start = time.time()
    rf_preds = rf_clf.predict(X_test)
    rf_proba = rf_clf.predict_proba(X_test)
    eval_latency = time.time() - t_eval_start

    accuracy = float(accuracy_score(y_raw_test, rf_preds))
    prec, rec, f1, _ = precision_recall_fscore_support(y_raw_test, rf_preds, average='weighted', zero_division=0)
    cm = confusion_matrix(y_raw_test, rf_preds).tolist()
    unique_labels = sorted(list(set(y_raw_test)))

    # Compute False Positive Rate on Benign/Normal class
    # FPR = FP / (FP + TN)
    if "Benign" in unique_labels:
        benign_idx = unique_labels.index("Benign")
        benign_actual = (y_raw_test == "Benign")
        benign_predicted_attack = (rf_preds != "Benign") & benign_actual
        fp_count = int(np.sum(benign_predicted_attack))
        tn_count = int(np.sum((rf_preds == "Benign") & benign_actual))
        fpr = float(fp_count / (fp_count + tn_count)) if (fp_count + tn_count) > 0 else 0.0
    else:
        fpr = 0.0

    # Benchmark vs Targets
    acc_pass = accuracy >= 0.95
    fpr_pass = fpr < 0.03
    eval_time_pass = eval_latency < 2.0

    print("\n" + "=" * 70)
    print("EVALUATION RESULTS & TARGET BENCHMARKS")
    print("=" * 70)
    print(f"Accuracy:                 {accuracy * 100:.2f}%  [Target: >= 95.00%] -> {'PASS' if acc_pass else 'FAIL'}")
    print(f"False Positive Rate (FPR): {fpr * 100:.2f}%  [Target: < 3.00%]   -> {'PASS' if fpr_pass else 'FAIL'}")
    print(f"Precision (Weighted):     {prec * 100:.2f}%")
    print(f"Recall (Weighted):        {rec * 100:.2f}%")
    print(f"F1-Score (Weighted):      {f1 * 100:.2f}%")
    print(f"Severity Eval Latency:    {eval_latency:.4f}s [Target: < 2.00s]   -> {'PASS' if eval_time_pass else 'FAIL'}")
    print("-" * 70)
    print(classification_report(y_raw_test, rf_preds, zero_division=0))

    # Feature Importances
    importances = rf_clf.feature_importances_
    feat_importance_dict = {
        name: float(imp) for name, imp in sorted(zip(LIVE_FEATURE_NAMES, importances), key=lambda x: x[1], reverse=True)
    }

    # 7. Save Models and Metadata
    rf_model_file = os.path.join(MODELS_DIR, "rf_v1.joblib")
    dt_model_file = os.path.join(MODELS_DIR, "dt_v1.joblib")
    meta_file = os.path.join(MODELS_DIR, "metadata.json")

    joblib.dump(rf_clf, rf_model_file)
    joblib.dump(dt_clf, dt_model_file)

    metadata = {
        "model_version": "rf_v1",
        "created_at": datetime.now().isoformat(),
        "algorithm": "RandomForestClassifier(n_estimators=50, max_depth=16)",
        "alternative_algorithm": "DecisionTreeClassifier(max_depth=16)",
        "features": LIVE_FEATURE_NAMES,
        "feature_count": len(LIVE_FEATURE_NAMES),
        "target_classes": unique_labels,
        "metrics": {
            "accuracy": round(accuracy, 4),
            "precision": round(float(prec), 4),
            "recall": round(float(rec), 4),
            "f1_score": round(float(f1), 4),
            "false_positive_rate": round(fpr, 4),
            "evaluation_latency_seconds": round(eval_latency, 4),
            "training_time_seconds": round(rf_train_time, 2)
        },
        "targets": {
            "accuracy_target": ">= 95.0%",
            "accuracy_result": f"{accuracy * 100:.2f}%",
            "accuracy_status": "PASS" if acc_pass else "FAIL",
            "fpr_target": "< 3.0%",
            "fpr_result": f"{fpr * 100:.2f}%",
            "fpr_status": "PASS" if fpr_pass else "FAIL",
            "latency_target": "< 2.0s",
            "latency_result": f"{eval_latency:.3f}s",
            "latency_status": "PASS" if eval_time_pass else "FAIL"
        },
        "confusion_matrix": cm,
        "labels": unique_labels,
        "validation_split": {
            "method": "Stratified hold-out (80/20), random_state=42, stratified on the raw dataset label",
            "train_ratio": 0.8,
            "test_ratio": 0.2,
            "train_samples": int(len(X_train)),
            "test_samples": int(len(X_test)),
            "evaluated_on": "test_samples",
        },
        "feature_importances": feat_importance_dict,
        "dataset_distribution": label_dist
    }

    with open(meta_file, "w") as f:
        json.dump(metadata, f, indent=2)

    print(f"[+] Saved models to:")
    print(f"    - Primary:     {rf_model_file}")
    print(f"    - Alternative: {dt_model_file}")
    print(f"    - Metadata:    {meta_file}")
    print("=" * 70)
    return metadata


if __name__ == "__main__":
    train_and_evaluate()
