"""
NetGuard Machine Learning Detector Module
Handles Random Forest model loading, robust CSV preprocessing, feature imputation,
traffic anomaly prediction, and evaluation metrics computation.
"""

import os
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score
)

from backend.config import ML_MODEL_PATH


# Cached model bundle in memory
_CACHED_MODEL_BUNDLE = None


def load_ml_model(model_path=ML_MODEL_PATH):
    """
    Loads and caches the trained Random Forest model bundle and pipeline.
    Returns (model_bundle, error_message).
    """
    global _CACHED_MODEL_BUNDLE
    if _CACHED_MODEL_BUNDLE is not None:
        return _CACHED_MODEL_BUNDLE, None

    if not os.path.exists(model_path):
        return None, (
            f"Trained model bundle not found at '{model_path}'. "
            "Please run `python train_model.py` to train and save the model."
        )

    try:
        bundle = joblib.load(model_path)
        _CACHED_MODEL_BUNDLE = bundle
        return bundle, None
    except Exception as e:
        return None, f"Failed to load machine learning model bundle: {str(e)}"


def get_model_evaluation_metrics():
    """
    Returns the held-out test set evaluation metrics stored in the model bundle.
    """
    bundle, err = load_ml_model()
    if err or not bundle:
        return None
    return bundle.get("metrics")


def preprocess_and_predict(df_input, model_bundle=None):
    """
    Preprocesses uploaded CSV dataframe, validates features, handles missing/incompatible
    attributes, imputes NaNs/infs, and predicts whether each network flow is Normal or Suspicious.

    Returns:
        tuple: (df_result, summary_stats, warnings_list, error_message)
    """
    if model_bundle is None:
        model_bundle, err = load_ml_model()
        if err:
            return None, None, [], err

    if df_input is None or df_input.empty:
        return None, None, [], "The uploaded CSV file is empty."

    df = df_input.copy()
    # Strip whitespace from column names
    df.columns = df.columns.str.strip()

    expected_features = model_bundle["feature_cols"]
    feature_medians = model_bundle["feature_medians"]
    model = model_bundle["model"]

    # Check for Ground Truth label column (e.g. Label, class, Attack)
    has_ground_truth = False
    ground_truth_col = None
    for candidate in ["Label", "label", "Attack", "attack", "Class", "class"]:
        if candidate in df.columns:
            has_ground_truth = True
            ground_truth_col = candidate
            break

    # Check feature compatibility
    present_features = [col for col in expected_features if col in df.columns]
    missing_features = [col for col in expected_features if col not in df.columns]

    # Incompatibility check: require at least 5 matching network features
    if len(present_features) < 5:
        return None, None, [], (
            f"Incompatible CSV format! Only {len(present_features)} of {len(expected_features)} "
            "expected network flow features were detected. Please ensure the CSV contains network "
            "traffic flow features compatible with CICIDS2017 / CICFlowMeter "
            "(e.g., 'Flow Duration', 'Total Fwd Packets', 'Packet Length Mean', etc.)."
        )

    warnings = []
    if missing_features:
        warnings.append(
            f"Notice: {len(missing_features)} of {len(expected_features)} features were missing in "
            f"the uploaded CSV and have been imputed using training set medians (e.g., {', '.join(missing_features[:3])}...)."
        )

    # Build aligned feature matrix X
    aligned_df = pd.DataFrame(index=df.index)
    for col in expected_features:
        if col in df.columns:
            aligned_df[col] = pd.to_numeric(df[col], errors="coerce")
        else:
            # Impute missing column with training set median
            aligned_df[col] = feature_medians.get(col, 0.0)

    # Replace infinite values with NaN
    aligned_df.replace([np.inf, -np.inf], np.nan, inplace=True)

    # Use the stored training medians directly. This avoids relying on the
    # scikit-learn private imputer state, which can change between versions.
    for col in expected_features:
        aligned_df[col] = aligned_df[col].fillna(feature_medians.get(col, 0.0))
    X_imputed = aligned_df.to_numpy(dtype=float)

    # Model inference
    predictions = model.predict(X_imputed)
    probabilities = model.predict_proba(X_imputed)

    # Attach results to dataframe
    result_df = df.copy()
    result_df["ml_prediction"] = ["Suspicious" if p == 1 else "Normal" for p in predictions]
    result_df["ml_prediction_code"] = predictions
    result_df["prob_normal"] = probabilities[:, 0]
    result_df["prob_suspicious"] = probabilities[:, 1]
    result_df["confidence"] = np.max(probabilities, axis=1)
    result_df["confidence_str"] = [f"{c * 100:.1f}%" for c in result_df["confidence"]]

    # Evaluation against ground truth if present
    batch_eval = None
    if has_ground_truth:
        y_true_binary = (result_df[ground_truth_col].astype(str).str.strip().str.upper() != "BENIGN").astype(int)
        result_df["true_binary"] = y_true_binary
        result_df["ground_truth_status"] = ["Suspicious" if y == 1 else "Normal" for y in y_true_binary]
        result_df["is_correct"] = (result_df["ml_prediction_code"] == y_true_binary)

        # Batch metrics
        batch_acc = float(accuracy_score(y_true_binary, predictions))
        batch_prec = float(precision_score(y_true_binary, predictions, pos_label=1, zero_division=0))
        batch_rec = float(recall_score(y_true_binary, predictions, pos_label=1, zero_division=0))
        batch_f1 = float(f1_score(y_true_binary, predictions, pos_label=1, zero_division=0))
        
        batch_cm = confusion_matrix(y_true_binary, predictions, labels=[0, 1])
        b_tn, b_fp, b_fn, b_tp = batch_cm.ravel()

        batch_eval = {
            "accuracy": batch_acc,
            "precision": batch_prec,
            "recall": batch_rec,
            "f1_score": batch_f1,
            "confusion_matrix": {
                "tn": int(b_tn),
                "fp": int(b_fp),
                "fn": int(b_fn),
                "tp": int(b_tp),
                "matrix": batch_cm.tolist()
            },
            "ground_truth_counts": df[ground_truth_col].value_counts().to_dict()
        }

    # Summary statistics
    total_records = len(result_df)
    suspicious_count = int((predictions == 1).sum())
    normal_count = int((predictions == 0).sum())
    suspicious_ratio = (suspicious_count / total_records * 100) if total_records > 0 else 0.0
    avg_confidence = float(result_df["confidence"].mean()) * 100 if total_records > 0 else 0.0
    high_confidence_count = int((result_df["confidence"] >= 0.90).sum())

    summary_stats = {
        "total_records": total_records,
        "suspicious_count": suspicious_count,
        "normal_count": normal_count,
        "suspicious_ratio": suspicious_ratio,
        "avg_confidence": avg_confidence,
        "high_confidence_count": high_confidence_count,
        "has_ground_truth": has_ground_truth,
        "ground_truth_col": ground_truth_col,
        "batch_eval": batch_eval,
        "features_used": len(present_features),
        "total_expected_features": len(expected_features)
    }

    return result_df, summary_stats, warnings, None
