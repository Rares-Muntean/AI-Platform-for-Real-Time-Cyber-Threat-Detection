import logging
import os
import threading
import time

from flask import Flask, jsonify, request
from helpers.config import save_config
from flask import Flask

logging.getLogger("werkzeug").setLevel(logging.ERROR)

def start_control_server(cfg, firewall, calibrator, port: int = 5005):
    app = Flask(__name__)

    @app.get("/status")
    def status():
        with firewall._lock:
            blocked_ips = list(firewall.active_blocks.keys())
        with calibrator.guard_lock:
            threshold = float(calibrator.guard.threshold)

        return jsonify({
            "agent": "VELOX",
            "captureMode": cfg["capture_mode"],
            "interface": cfg["interface"],
            "firewallEnabled": cfg["firewall_enabled"],
            "blockDurationSeconds": cfg["block_duration_seconds"],
            "deviceIpOverride": cfg["device_ip_override"],
            "threshold": threshold,
            "activeBlocks": blocked_ips,
            "calibration": calibrator.get_status(),
        })

    @app.post("/calibrate")
    def calibrate():
        body = request.get_json(silent=True) or {}
        ok, msg = calibrator.start_calibration(
            duration=body.get("duration", 30),
            mode=body.get("mode", "update"),
        )
        return (
            jsonify({
                "started": ok,
                "message": msg,
                "calibration": calibrator.get_status(),
            }),
            (202 if ok else 409),
        )

    @app.post("/config")
    def update_config():
        body = request.get_json(silent=True) or {}
        allowed_keys = {
            "interface",
            "capture_mode",
            "firewall_enabled",
            "block_duration_seconds",
            "protect_management_ports",
            "device_ip_override",
        }
        for key in allowed_keys:
            if key in body:
                cfg[key] = body[key]

        save_config(cfg)


        def delayed_restart():
            time.sleep(0.4)
            firewall.cleanup()
            os._exit(0)

        threading.Thread(target=delayed_restart, daemon=True).start()
        return jsonify(
            {"saved": True, "message": "Restarting agent...", "config": cfg}
        )

    threading.Thread(
        target=lambda: app.run(
            host="0.0.0.0", port=port, debug=False, use_reloader=False
        ),
        daemon=True,
    ).start()