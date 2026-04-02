"""
run.py — Unified launcher for the Adaptive AI Firewall.

Usage:
  python run.py server              Start the Flask dashboard API (no root needed)
  python run.py firewall            Start realtime packet capture (needs sudo)
  python run.py train               Train the real-time ML model (no dataset needed)
  python run.py train --mode unsw --data dataset.parquet
"""

import os
import sys
import argparse

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)


def cmd_server(args):
    """Start the Flask backend dashboard API."""
    os.chdir(os.path.join(ROOT, "backend"))
    sys.path.insert(0, os.path.join(ROOT, "backend"))
    from backend.app import app
    print("[*] Starting Flask dashboard on http://0.0.0.0:5000 …")
    print("[*] ML Dashboard at http://localhost:5000/ml-dashboard")
    app.run(debug="--debug" in sys.argv, host="0.0.0.0", port=5000, threaded=True)


def cmd_firewall(args):
    """Start the realtime packet capture engine (requires root)."""
    if os.geteuid() != 0:
        print("[!] Firewall capture requires root: sudo python run.py firewall")
        sys.exit(1)
    from firewall_engine.capture import CaptureEngine
    engine = CaptureEngine(queue_num=0)
    engine.run()


def cmd_train(args):
    """Train the ML model."""
    sys.path.insert(0, os.path.join(ROOT, "ml_model"))
    from ml_model.train_model import train_realtime, train_unsw

    mode = getattr(args, "mode", "realtime")
    if mode == "unsw":
        data = getattr(args, "data", None)
        if not data:
            print("[!] --data <path> is required for --mode unsw")
            sys.exit(1)
        train_unsw(data)
    else:
        train_realtime()


def main():
    parser = argparse.ArgumentParser(
        description="Adaptive AI Firewall — Unified Launcher",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # server
    sub.add_parser("server", help="Start Flask API dashboard")

    # firewall
    sub.add_parser("firewall", help="Start realtime packet capture (need sudo)")

    # train
    train_p = sub.add_parser("train", help="Train the ML model")
    train_p.add_argument("--mode", choices=["realtime", "unsw"], default="realtime")
    train_p.add_argument("--data", type=str, default=None,
                         help="Path to UNSW-NB15 parquet file")

    args = parser.parse_args()

    if args.command == "server":
        cmd_server(args)
    elif args.command == "firewall":
        cmd_firewall(args)
    elif args.command == "train":
        cmd_train(args)


if __name__ == "__main__":
    main()
