import os
import sys
import json
import time
import joblib

# Fix path to load ml_model regardless of execution folder
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from firewall_engine.iptables_controller import IPTablesController
from firewall_engine.attack_classifier import AttackClassifier
from ml_model.preprocess import process_single_packet

class DecisionEngine:
    def __init__(self):
        self.iptables = IPTablesController()
        self.classifier = AttackClassifier()
        self.log_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs", "firewall_logs.json")
        # Search for model in multiple locations (standardize on one if possible later)
        root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        possible_dirs = [
            os.path.join(root_dir, "ml_model"),
            os.path.join(root_dir, "model")
        ]
        
        found_dir = None
        for d in possible_dirs:
            if os.path.exists(os.path.join(d, "model.pkl")) and \
               os.path.exists(os.path.join(d, "preprocessor.pkl")) and \
               os.path.exists(os.path.join(d, "feature_schema.pkl")):
                found_dir = d
                break
        
        if found_dir:
            model_path = os.path.join(found_dir, "model.pkl")
            self.preprocessor_path = os.path.join(found_dir, "preprocessor.pkl")
            self.schema_path = os.path.join(found_dir, "feature_schema.pkl")
            try:
                self.model = joblib.load(model_path)
                print(f"[*] Loaded ML model successfully from {found_dir}.")
            except Exception as e:
                print(f"[!] Warning: Could not load ML model from {found_dir} ({e}).")
        else:
            print("[!] ML model files missing from both ml_model/ and model/ directories.")
            print("[!] Proceeding with heuristic mode only.")

        log_dir = os.path.dirname(self.log_file)
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
            
        # Optional: initialize log file if doesn't exist
        if not os.path.exists(self.log_file):
            with open(self.log_file, "w") as f:
                pass
            
    def evaluate_packet(self, features):
        src_ip = features.get('srcip', '0.0.0.0')
        dst_ip = features.get('dstip', '0.0.0.0')
        protocol = features.get('proto', 'unknown')
        
        X_test = None
        # Predict using IsolationForest if available
        if self.model is not None and os.path.exists(self.preprocessor_path):
            X_test_transformed = process_single_packet(features, self.preprocessor_path, self.schema_path)
            if X_test_transformed is not None:
                X_test = X_test_transformed
            
        anomaly_score = 0.0
        prediction = 1 # 1 is normal, -1 is anomaly in isolation forest
        
        if X_test is not None:
            raw_score = self.model.decision_function(X_test)[0]
            prediction = self.model.predict(X_test)[0]
            
            # Map isolation forest score to a 0-1 threat score
            anomaly_score = max(0, -raw_score * 2.0)
            if prediction == -1:
                anomaly_score += 0.5
            anomaly_score = min(1.0, anomaly_score)
            print(f"[DEBUG] Model prediction: {prediction}, raw: {raw_score:.4f}, final: {anomaly_score:.4f}")
        else:
            print("[DEBUG] X_test is None, skipping ML prediction.")
            pass
            
        heuristic_attack = self.classifier.classify(features)
        
        action = "ALLOW"
        attack_type = "None"
        
        # We trigger on model prediction or heuristic severity
        if prediction == -1 or anomaly_score > 0.6 or heuristic_attack != "None":
            attack_type = heuristic_attack if heuristic_attack != "None" else "AI Anomaly"
            action = "BLOCK"
            self.iptables.block_ip(src_ip)
            
        self.log_event(src_ip, dst_ip, protocol, attack_type, anomaly_score, action)
        
        return action == "ALLOW"
        
    def log_event(self, src_ip, dst_ip, protocol, attack_type, anomaly_score, action):
        log_entry = {
            "timestamp": time.time(),
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "protocol": protocol,
            "attack_type": attack_type,
            "anomaly_score": round(float(anomaly_score), 3),
            "action": action
        }
        
        with open(self.log_file, "a") as f:
            f.write(json.dumps(log_entry) + "\n")
