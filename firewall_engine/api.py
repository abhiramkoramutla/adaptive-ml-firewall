from flask import Flask, jsonify
import time
import json
import os

app = Flask(__name__)

# Path to shared results (this could be a database or a shared memory object,
# but for simplicity in modular scripts, we'll use a JSON log)
LOG_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs", "realtime_flows.json")

@app.route('/api/flow')
def get_flows():
    """
    Returns the latest analyzed flows.
    """
    if not os.path.exists(LOG_FILE):
        return jsonify([])
        
    flows = []
    try:
        with open(LOG_FILE, "r") as f:
            lines = f.readlines()[-20:] # Last 20 results
            for line in lines:
                flows.append(json.loads(line))
    except Exception as e:
        return jsonify({"error": str(e)}), 500
        
    return jsonify(flows[::-1]) # Newest first

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
