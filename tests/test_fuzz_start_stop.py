import os
import time
import subprocess
import requests

ECHO = os.path.join(os.path.dirname(__file__), "..", "examples", "local_echo_server.py")

def test_fuzz_start_stop():
    # Start echo server
    echo = subprocess.Popen(["python", ECHO, "9001"])
    time.sleep(0.8)

    # Start backend
    api = subprocess.Popen(["uvicorn", "vulnspiral.server:app", "--port", "8001"])
    time.sleep(1.2)

    try:
        # Start fuzz
        payload = {
            "target": "127.0.0.1:9001",
            "interface": "lo",
            "duration_seconds": 5,
            "engine": "custom",
            "seed_files": [],
            "protocol_hint": "tcp",
            "extra_opts": {"confirm_remote": True}
        }
        r = requests.post("http://127.0.0.1:8001/api/fuzz/start", json=payload, timeout=10)
        assert r.status_code == 200
        run_id = r.json()["run_id"]

        # wait to finish
        time.sleep(7)

        # pcap may be present if privileges allowed (best-effort)
        r_pcap = requests.get(f"http://127.0.0.1:8001/api/fuzz/pcap/{run_id}", timeout=5)
        assert r_pcap.status_code in (200, 404)

    finally:
        api.terminate(); api.wait()
        echo.terminate(); echo.wait()
