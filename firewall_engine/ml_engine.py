import os
import joblib
import numpy as np
import pandas as pd
import logging

logger = logging.getLogger("MLEngine")

class MLEngine:
    def __init__(self, model_path, scaler_path, threshold_percentile=95):
        self.model = None
        self.scaler = None
        self.threshold = -0.05  # Sensible default (slightly below 0)
        self.threshold_percentile = threshold_percentile

        threshold_path = os.path.join(os.path.dirname(model_path), 'threshold.pkl')

        if os.path.exists(model_path) and os.path.exists(scaler_path):
            try:
                self.model  = joblib.load(model_path)
                self.scaler = joblib.load(scaler_path)

                # Prefer the calibrated threshold saved during training
                if os.path.exists(threshold_path):
                    self.threshold = joblib.load(threshold_path)
                    logger.info(f"Loaded calibrated threshold: {self.threshold:.4f}")
                else:
                    # Fallback: use model offset (less accurate)
                    self.threshold = getattr(self.model, 'offset_', -0.05)
                    logger.warning(f"threshold.pkl not found; using model.offset_={self.threshold:.4f}")

                logger.info(f"Loaded model and scaler. Threshold: {self.threshold:.4f}")
            except Exception as e:
                logger.error(f"Failed to load ML models: {e}")
        else:
            logger.warning("ML model or scaler not found. Falling back to heuristic/safe mode.")

    def predict(self, features):
        if not self.model or not self.scaler:
            return 1.0, 0.0 # Fail-safe: Mark as Normal (1.0) with 0 score

        # Convert features dict to a named DataFrame so sklearn doesn't warn
        # about missing feature names (scaler was fitted with a DataFrame).
        FEATURE_ORDER = [
            'packet_rate', 'byte_rate', 'duration', 'iat_mean', 'iat_std',
            'syn_ratio', 'ack_ratio', 'fin_ratio', 'avg_packet_size'
        ]
        try:
            X = pd.DataFrame([[
                features['packet_rate'],
                features['byte_rate'],
                features['duration'],
                features['iat_mean'],
                features['iat_std'],
                features['syn_ratio'],
                features['ack_ratio'],
                features['fin_ratio'],
                features['avg_packet_size']
            ]], columns=FEATURE_ORDER)

            X_scaled = self.scaler.transform(X)
            score = self.model.decision_function(X_scaled)[0]

            # IsolationForest decision_function: > 0 is normal, < 0 is anomaly
            is_anomaly = score < self.threshold

            return score, 1.0 if is_anomaly else 0.0
        except Exception as e:
            logger.error(f"Prediction error: {e}")
            return 0.0, 0.0  # Fail-safe
