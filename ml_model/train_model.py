import os
import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("Train")

FEATURES = [
    'packet_rate', 'byte_rate', 'duration', 'iat_mean', 'iat_std',
    'syn_ratio', 'ack_ratio', 'fin_ratio', 'avg_packet_size'
]

def generate_synthetic_data(n_samples=10000):
    """Generate representative synthetic data for the new feature set."""
    rng = np.random.default_rng(42)
    
    # Normal traffic
    normal = pd.DataFrame({
        'packet_rate': rng.uniform(1, 100, n_samples),
        'byte_rate': rng.uniform(500, 50000, n_samples),
        'duration': rng.uniform(1, 10, n_samples),
        'iat_mean': rng.uniform(0.01, 0.2, n_samples),
        'iat_std': rng.uniform(0.001, 0.05, n_samples),
        'syn_ratio': rng.uniform(0.01, 0.1, n_samples),
        'ack_ratio': rng.uniform(0.8, 1.0, n_samples),
        'fin_ratio': rng.uniform(0.01, 0.1, n_samples),
        'avg_packet_size': rng.uniform(60, 1500, n_samples),
        'label': 0
    })
    
    # Attack traffic (DoS/Floods/Scans)
    attack = pd.DataFrame({
        'packet_rate': rng.uniform(500, 5000, n_samples // 10),
        'byte_rate': rng.uniform(100000, 1000000, n_samples // 10),
        'duration': rng.uniform(0.1, 2, n_samples // 10),
        'iat_mean': rng.uniform(0.0001, 0.005, n_samples // 10),
        'iat_std': rng.uniform(0.00001, 0.001, n_samples // 10),
        'syn_ratio': rng.choice([0.9, 0.01], n_samples // 10), # SYN flood or high-rate data
        'ack_ratio': rng.uniform(0.1, 0.5, n_samples // 10),
        'fin_ratio': rng.uniform(0.0, 0.05, n_samples // 10),
        'avg_packet_size': rng.uniform(40, 100, n_samples // 10),
        'label': 1
    })
    
    return pd.concat([normal, attack])

def train_realtime():
    """Train IsolationForest on synthetic 9-feature traffic data."""
    data = generate_synthetic_data()
    X = data[FEATURES]
    y = data['label']

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Train only on normal data (standard IsolationForest practice)
    X_train = X_scaled[y == 0]

    model = IsolationForest(
        n_estimators=200,
        contamination=0.08,   # ~8% of traffic expected to be anomalous
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_train)

    # Evaluation on full dataset
    y_pred_raw = model.predict(X_scaled)  # 1=normal, -1=anomaly
    y_pred = np.where(y_pred_raw == -1, 1, 0)

    precision = precision_score(y, y_pred, zero_division=0)
    recall    = recall_score(y, y_pred,    zero_division=0)
    f1        = f1_score(y, y_pred,         zero_division=0)

    logger.info("Training Complete.")
    logger.info(f"Precision: {precision:.4f}, Recall: {recall:.4f}, F1: {f1:.4f}")

    # ── Calibrate threshold from actual score distributions ────────────────
    # model.offset_ is calibrated on normal-only training data which makes it
    # too conservative. Instead compute the midpoint between worst normal and
    # best attack score so it reliably fires on real attack traffic.
    all_scores = model.decision_function(X_scaled)
    normal_scores = all_scores[y == 0]
    attack_scores = all_scores[y == 1]

    normal_5th  = np.percentile(normal_scores, 5)   # most anomalous 5% of normal
    attack_95th = np.percentile(attack_scores, 95)  # least anomalous 5% of attack
    threshold   = (normal_5th + attack_95th) / 2.0

    logger.info(f"Calibrated threshold: {threshold:.4f}  "
                f"(normal_5th={normal_5th:.4f}, attack_95th={attack_95th:.4f})")

    # Save artifacts
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    joblib.dump(model,     os.path.join(root_dir, 'ml_model', 'model.pkl'))
    joblib.dump(scaler,    os.path.join(root_dir, 'ml_model', 'scaler.pkl'))
    joblib.dump(threshold, os.path.join(root_dir, 'ml_model', 'threshold.pkl'))
    logger.info("Saved model.pkl, scaler.pkl, and threshold.pkl to ml_model/")
    return threshold


def train_unsw(data_path: str):
    """Train using UNSW-NB15 parquet dataset (not yet implemented)."""
    logger.warning("UNSW-NB15 training mode is not implemented yet.")
    logger.warning("Run without --mode unsw to use synthetic realtime training.")
    raise NotImplementedError("UNSW training not yet implemented. Use: python run.py train")


if __name__ == "__main__":
    train_realtime()
