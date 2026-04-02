"""
app.py — Flask application factory for the Adaptive AI Firewall backend.
"""

import os
import sys

# Ensure the project root is in sys.path
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# Add backend dir to path for routes import
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, send_from_directory, make_response
from flask_cors import CORS

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

if os.geteuid() != 0:
    print("[!] Not running as root — iptables block/unblock endpoints may fail.")
    print("[!] Capture engine will NOT start.")

app = Flask(
    __name__,
    template_folder=os.path.join(ROOT, "dashboard", "templates"),
    static_folder=os.path.join(ROOT, "static"),
)

# Enable CORS for React dev server (port 5173) and production
CORS(app, resources={r"/api/*": {"origins": "*"}})


# ── React ML Dashboard ────────────────────────────────────────────────────────

REACT_DIST = os.path.join(ROOT, "frontend-react", "dist")


@app.route("/ml-dashboard")
@app.route("/ml-dashboard/<path:path>")
def serve_ml_dashboard(path=""):
    if not os.path.exists(REACT_DIST):
        return (
            "ML Dashboard not built. Run: cd frontend-react && npm run build",
            404,
        )
    if path and os.path.exists(os.path.join(REACT_DIST, path)):
        return send_from_directory(REACT_DIST, path)
    return send_from_directory(REACT_DIST, "index.html")


@app.route("/assets/<path:path>")
def serve_assets(path):
    assets_dir = os.path.join(REACT_DIST, "assets")
    target = os.path.join(assets_dir, path)
    if not os.path.exists(target):
        return "Asset not found", 404
    resp = make_response(send_from_directory(assets_dir, path))
    if path.endswith(".css"):
        resp.headers["Content-Type"] = "text/css"
    elif path.endswith(".js"):
        resp.headers["Content-Type"] = "application/javascript"
    return resp


# ── Register API routes ───────────────────────────────────────────────────────
import routes
routes.register_endpoints(app)


if __name__ == "__main__":
    if os.geteuid() == 0:
        print("[INFO] Starting unified stack (Flask + Capture Engine)...")
        import threading
        from firewall_engine.capture import CaptureEngine
        engine = CaptureEngine(queue_num=0)
        routes.set_engine(engine)

        flask_thread = threading.Thread(
            target=app.run,
            kwargs={"host": "0.0.0.0", "port": 5000, "debug": False, "use_reloader": False, "threaded": True},
            daemon=True
        )
        flask_thread.start()
        
        try:
            engine.run()
        except KeyboardInterrupt:
            print("[*] Shutting down...")
    else:
        app.run(debug=True, host="0.0.0.0", port=5000, threaded=True)
