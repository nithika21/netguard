"""
NetGuard Machine Learning Training Script
Trains a Random Forest classifier on actual CICIDS2017 network traffic records.
Evaluates model on a held-out test set (precision, recall, F1-score, confusion matrix)
and saves the trained model and preprocessing pipeline for reuse in NetGuard.
"""

import os
import sys
import time
import urllib.request
from datetime import datetime
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    classification_report
)
from sklearn.model_selection import train_test_split

# Ensure config paths are available
PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_DIR)
from backend.config import DATA_DIR, ML_MODEL_PATH, DATASET_CSV_PATH, SAMPLE_CSV_PATH


CICIDS2017_RAW_URL = (
    "https://raw.githubusercontent.com/avdhesh201/Intrusion-Detection-System/master/CICIDS2017_sample.csv"
)


def ensure_dataset():
    """Ensures the CICIDS2017 dataset is downloaded and stored in the data directory."""
    os.makedirs(DATA_DIR, exist_ok=True)
    if not os.path.exists(DATASET_CSV_PATH):
        print(f"[*] Downloading CICIDS2017 dataset to {DATASET_CSV_PATH}...")
        req = urllib.request.Request(CICIDS2017_RAW_URL, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req) as resp, open(DATASET_CSV_PATH, "wb") as f:
            total_bytes = 0
            while chunk := resp.read(1024 * 1024):
                f.write(chunk)
                total_bytes += len(chunk)
                print(f"    Downloaded {total_bytes / (1024 * 1024):.1f} MB...", end="\r")
        print(f"\n[+] Download complete! File size: {os.path.getsize(DATASET_CSV_PATH) / (1024 * 1024):.2f} MB")
    else:
        print(f"[+] Dataset found at: {DATASET_CSV_PATH} ({os.path.getsize(DATASET_CSV_PATH) / (1024 * 1024):.2f} MB)")


def load_and_preprocess_data():
    """
    Loads raw CICIDS2017 traffic records, cleans column names,
    replaces infinite values with NaN, extracts target labels,
    and sets up numerical feature matrix.
    """
    print("[*] Reading dataset CSV...")
    df = pd.read_csv(DATASET_CSV_PATH)
    print(f"[+] Loaded raw dataset: {df.shape[0]:,} rows, {df.shape[1]} columns")

    # Clean whitespace in column names (common in CICIDS2017 datasets)
    df.columns = df.columns.str.strip()

    if "Label" not in df.columns:
        # Search for any column named label case-insensitively
        label_cols = [c for c in df.columns if c.lower() == "label"]
        if label_cols:
            df.rename(columns={label_cols[0]: "Label"}, inplace=True)
        else:
            raise ValueError("Required 'Label' column not found in dataset!")

    # Clean label values
    df["Label"] = df["Label"].astype(str).str.strip()
    attack_counts = df["Label"].value_counts().to_dict()
    print("[*] Dataset original class distribution:")
    for lbl, cnt in attack_counts.items():
        print(f"    - {lbl}: {cnt:,} records ({cnt / len(df) * 100:.1f}%)")

    # Binary classification: 0 = Normal (BENIGN), 1 = Suspicious (Attacks)
    y = (df["Label"].str.upper() != "BENIGN").astype(int)
    normal_cnt = int((y == 0).sum())
    suspicious_cnt = int((y == 1).sum())
    print(f"[+] Binary mapping: Normal = {normal_cnt:,} ({normal_cnt / len(y) * 100:.1f}%), "
          f"Suspicious = {suspicious_cnt:,} ({suspicious_cnt / len(y) * 100:.1f}%)")

    # Feature columns: all columns except target label
    feature_cols = [c for c in df.columns if c != "Label"]

    # Convert all feature columns to numeric, replacing invalid strings with NaN
    X = df[feature_cols].apply(pd.to_numeric, errors="coerce")

    # Replace infinite values (which can occur in Flow Bytes/s and Flow Packets/s) with NaN
    X.replace([np.inf, -np.inf], np.nan, inplace=True)

    null_count_before = int(X.isnull().sum().sum())
    print(f"[*] Infinite or missing values detected: {null_count_before:,} entries across features.")

    return X, y, df["Label"], feature_cols, attack_counts


def train_and_evaluate():
    """
    Trains Random Forest classifier on 80% train split,
    evaluates strictly on 20% held-out test split,
    and returns model bundle and sample test DataFrame.
    """
    ensure_dataset()
    X, y, original_labels, feature_cols, attack_counts = load_and_preprocess_data()

    # 80/20 Stratified train-test split to preserve class proportions
    print("[*] Splitting dataset into 80% training set and 20% held-out test set...")
    X_train, X_test, y_train, y_test, labels_train, labels_test = train_test_split(
        X, y, original_labels,
        test_size=0.20,
        random_state=42,
        stratify=y
    )

    print(f"    - Training set size: {len(X_train):,} records")
    print(f"    - Held-out test set size: {len(X_test):,} records")

    # Preprocessing Pipeline: Median Imputer
    # Fits on training set only to prevent data leakage
    print("[*] Fitting SimpleImputer (strategy='median') on training features...")
    imputer = SimpleImputer(strategy="median")
    X_train_imputed = imputer.fit_transform(X_train)
    X_test_imputed = imputer.transform(X_test)

    # Store column-wise medians for fallback feature alignment
    feature_medians = dict(zip(feature_cols, imputer.statistics_))

    # Initialize Random Forest Classifier
    # - n_estimators=100: robust ensemble size
    # - max_depth=15: controls overfitting and ensures fast inference in Streamlit
    # - class_weight='balanced': compensates for class imbalance
    # - n_jobs=-1: fast parallel training
    print("[*] Training RandomForestClassifier (n_estimators=100, max_depth=15, class_weight='balanced')...")
    start_time = time.time()
    rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=15,
        min_samples_split=5,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )
    rf.fit(X_train_imputed, y_train)
    train_duration = time.time() - start_time
    print(f"[+] Model training completed in {train_duration:.2f} seconds.")

    # Strict Evaluation on Held-Out Test Set
    print("[*] Evaluating model performance on held-out test set (unseen data)...")
    y_pred = rf.predict(X_test_imputed)
    y_proba = rf.predict_proba(X_test_imputed)[:, 1]

    # Metrics calculation
    accuracy = float(accuracy_score(y_test, y_pred))
    precision_suspicious = float(precision_score(y_test, y_pred, pos_label=1, zero_division=0))
    recall_suspicious = float(recall_score(y_test, y_pred, pos_label=1, zero_division=0))
    f1_suspicious = float(f1_score(y_test, y_pred, pos_label=1, zero_division=0))

    precision_normal = float(precision_score(y_test, y_pred, pos_label=0, zero_division=0))
    recall_normal = float(recall_score(y_test, y_pred, pos_label=0, zero_division=0))
    f1_normal = float(f1_score(y_test, y_pred, pos_label=0, zero_division=0))

    f1_macro = float(f1_score(y_test, y_pred, average="macro", zero_division=0))
    f1_weighted = float(f1_score(y_test, y_pred, average="weighted", zero_division=0))

    # Confusion Matrix:
    # Rows: Actual Normal (0), Actual Suspicious (1)
    # Columns: Predicted Normal (0), Predicted Suspicious (1)
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()

    # Classification report as text and dict
    report_dict = classification_report(
        y_test, y_pred,
        target_names=["Normal", "Suspicious"],
        output_dict=True,
        zero_division=0
    )
    report_text = classification_report(
        y_test, y_pred,
        target_names=["Normal", "Suspicious"],
        zero_division=0
    )

    print("\n" + "=" * 60)
    print("           HELD-OUT TEST SET EVALUATION RESULTS           ")
    print("=" * 60)
    print(f"Overall Accuracy:        {accuracy * 100:.2f}%")
    print(f"Precision (Suspicious):  {precision_suspicious * 100:.2f}%")
    print(f"Recall (Suspicious):     {recall_suspicious * 100:.2f}%")
    print(f"F1-Score (Suspicious):   {f1_suspicious * 100:.2f}%")
    print(f"F1-Score (Macro):        {f1_macro * 100:.2f}%")
    print(f"F1-Score (Weighted):     {f1_weighted * 100:.2f}%")
    print("-" * 60)
    print("Confusion Matrix Breakdown:")
    print(f"  • True Normal (TN):      {tn:,} (correctly classified normal flows)")
    print(f"  • False Positive (FP):   {fp:,} (normal flows misclassified as suspicious)")
    print(f"  • False Negative (FN):   {fn:,} (attacks missed as normal)")
    print(f"  • True Suspicious (TP):  {tp:,} (attacks correctly flagged)")
    print("-" * 60)
    print("Full Classification Report:\n", report_text)
    print("=" * 60)

    # Top Feature Importances
    importances = rf.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]
    top_features = [
        {"feature": feature_cols[i], "importance": float(importances[i])}
        for i in sorted_idx[:20]
    ]

    print("\n[*] Top 10 Most Influential Network Traffic Features:")
    for rank, item in enumerate(top_features[:10], start=1):
        print(f"    {rank:2d}. {item['feature']:<30} {item['importance'] * 100:.2f}%")

    # Package model bundle
    model_bundle = {
        "model": rf,
        "imputer": imputer,
        "feature_cols": feature_cols,
        "feature_medians": feature_medians,
        "target_names": ["Normal", "Suspicious"],
        "metrics": {
            "test_size": int(len(y_test)),
            "train_size": int(len(y_train)),
            "accuracy": accuracy,
            "precision_suspicious": precision_suspicious,
            "recall_suspicious": recall_suspicious,
            "f1_suspicious": f1_suspicious,
            "precision_normal": precision_normal,
            "recall_normal": recall_normal,
            "f1_normal": f1_normal,
            "f1_macro": f1_macro,
            "f1_weighted": f1_weighted,
            "confusion_matrix": {
                "tn": int(tn),
                "fp": int(fp),
                "fn": int(fn),
                "tp": int(tp),
                "matrix": cm.tolist()
            },
            "top_features": top_features,
            "attack_breakdown": attack_counts,
            "trained_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "dataset_name": "CICIDS2017 Intrusion Detection Dataset (UNB / CIC)",
            "total_records": int(len(X)),
            "n_estimators": 100,
            "max_depth": 15
        }
    }

    # Save model bundle to disk
    print(f"\n[*] Saving trained model and preprocessing pipeline to {ML_MODEL_PATH}...")
    joblib.dump(model_bundle, ML_MODEL_PATH)
    file_size_mb = os.path.getsize(ML_MODEL_PATH) / (1024 * 1024)
    print(f"[+] Saved model bundle successfully! File size: {file_size_mb:.2f} MB")

    # Create a realistic, ready-to-test sample CSV for user testing
    # Take 800 balanced records from the held-out test set
    print("[*] Generating sample test CSV for Streamlit Packet Explorer...")
    test_indices = X_test.index
    df_test_full = pd.read_csv(DATASET_CSV_PATH).iloc[test_indices].copy()
    df_test_full.columns = df_test_full.columns.str.strip()

    # Stratified sample of ~800 records from test set
    sample_dfs = []
    for label, group in df_test_full.groupby("Label"):
        sample_size = min(len(group), max(50, int(800 * len(group) / len(df_test_full))))
        sample_dfs.append(group.sample(sample_size, random_state=42))
    sample_df = pd.concat(sample_dfs).sample(frac=1.0, random_state=42).reset_index(drop=True)

    sample_df.to_csv(SAMPLE_CSV_PATH, index=False)
    print(f"[+] Saved sample test dataset to {SAMPLE_CSV_PATH} ({len(sample_df)} records)")

    return model_bundle


if __name__ == "__main__":
    train_and_evaluate()
