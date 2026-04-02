# Adaptive AI Firewall

A complete, fully executable production-style AI-based firewall. It monitors traffic in real-time using NFQUEUE and Scapy, extracts UNSW-NB15 flow features, predicts anomalies using an Isolation Forest ML model, classifies the attack type using heuristics, blocks malicious IPs using `iptables`, and displays live updates on a modern TailwindCSS dashboard.

## System Requirements
- Linux OS (requires `iptables` and NFQUEUE support)
- Python 3.11+
- Root (`sudo`) privileges for network interception

## Step-by-Step Instructions

### 1. Install System Dependencies
First, ensure you have the required system libraries for building the NetfilterQueue Python bindings:
```bash
sudo apt-get update
sudo apt-get install build-essential python3-dev libnetfilter-queue-dev
```

### 2. Install Python Packages
Install the required libraries:
```bash
pip install -r requirements.txt
```

### 3. Train the ML Model
Place your `.parquet` dataset in the project directory (e.g., `UNSW_NB15_training-set.parquet`).
Run the training script to generate the preprocessor, feature schema, and Isolation Forest model `model.pkl`:
```bash
python ml_model/train_model.py --data path/to/dataset.parquet
```

*(Note: The model will be automatically saved to `ml_model/model.pkl`)*

### 4. Start the Flask Dashboard
In a separate terminal, start the backend to serve the UI and API endpoints. 
```bash
python backend/app.py
```
Access the dashboard at [http://localhost:5000](http://localhost:5000).

### 5. Start the Firewall Listener
In another terminal, start the packet capture and AI decision engine. **This must be run as root** to interact with `iptables` and the `NFQUEUE`.
```bash
sudo python firewall_engine/packet_listener.py
```

### 6. Configure IPTables (Handled Automatically)
The `packet_listener.py` automatically sets up the following `iptables` rule to route traffic to the AI engine on startup:
`iptables -I INPUT -j NFQUEUE --queue-num 0`

And removes it gracefully when you stop the script (`Ctrl+C`):
`iptables -D INPUT -j NFQUEUE --queue-num 0`

When an anomaly is detected, the engine will automatically block the IP:
`iptables -A INPUT -s <attacker_ip> -j DROP`

You can manually trigger an unblock from the Dashboard GUI or using iptables directly.

---

## Project Structure
- `ml_model/`: Dataset loading, data processing, Isolation Forest training.
- `firewall_engine/`: Scapy packet interception, FlowTracker feature extraction, heuristic classifier, AI inference, and iptables execution.
- `backend/`: Flask server and API router.
- `dashboard/templates/`: Tailwind UI structure.
- `static/`: JS Charts and CSS overrides.
- `logs/`: Real-time JSON log storage.
