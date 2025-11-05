#!/usr/bin/env python3
import os
import json
import shutil
from datetime import datetime

ITSAR_CITATIONS = [
    ":contentReference[oaicite:1]{index=1}",
    ":contentReference[oaicite:2]{index=2}",
]

# Simple CWE mapping by anomaly category
ANOMALY_CWE = {
    "size_overflow": ["CWE-119", "CWE-787"],
    "boundary_values": ["CWE-20", "CWE-193"],
    "invalid_utf8": ["CWE-176"],
    "special_chars": ["CWE-116"],
    "format_strings": ["CWE-134"],
    "null_bytes": ["CWE-170"],
    "random_noise": ["CWE-20"],
}

def heuristic_cvss(suspected_crash: bool, transport: str) -> float:
    """
    Very rough CVSS v3.1 base estimate for prioritization.
    If suspected crash observed => high availability impact.
    """
    if suspected_crash:
        return 9.1  # AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H (approx.)
    return 5.3  # AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L (approx.)

def collect(run_id: str, outdir: str = None):
    base = os.path.join(os.getcwd(), "runs", run_id)
    if not os.path.exists(base):
        raise SystemExit(f"Run {run_id} not found at {base}")
    outdir = outdir or os.path.join(base, "evidence")
    os.makedirs(outdir, exist_ok=True)

    # Copy pcap, logs, config, tool metadata
    for name in ("pcaps", "logs", "config.json", "tool.json"):
        src = os.path.join(base, name)
        if os.path.isdir(src):
            shutil.copytree(src, os.path.join(outdir, os.path.basename(src)), dirs_exist_ok=True)
        elif os.path.isfile(src):
            shutil.copy2(src, outdir)

    # Load config for anomaly profile & transport
    cfg_path = os.path.join(base, "config.json")
    transport = "tcp"
    anomalies = {}
    if os.path.isfile(cfg_path):
        try:
            cfg = json.load(open(cfg_path))
            transport = cfg.get("transport") or transport
            anomalies = (cfg.get("extra_opts") or {}).get("anomaly_profile") or {}
        except Exception:
            pass

    # Heuristic: suspected crash if >= 10 consecutive send errors recorded
    suspected = False
    logp = os.path.join(base, "logs", "run.log")
    if os.path.isfile(logp):
        try:
            txt = open(logp, "r", errors="ignore").read()
            # naive counter
            suspected = txt.count("send error") >= 10 or "Engine failed" in txt
        except Exception:
            pass

    cwe = sorted({c for k, ws in ANOMALY_CWE.items() for c in ws if anomalies.get(k, 0) > 0})
    cvss = heuristic_cvss(suspected, transport)

    summary = {
        "tool": "VulnSpiral",
        "version": json.load(open(os.path.join(base, "tool.json"), "r")).get("version", "unknown") if os.path.isfile(os.path.join(base, "tool.json")) else "unknown",
        "run_id": run_id,
        "collected_at": datetime.utcnow().isoformat() + "Z",
        "evidence_files": sorted(os.listdir(outdir)),
        "itsar_citations": ITSAR_CITATIONS,
        "anomaly_profile": anomalies,
        "cwe_tags": cwe,
        "cvss_estimate": cvss,
        "suspected_crash": suspected,
        "remediation": {
            "what_to_collect_next": [
                "DUT kernel logs (UART) around the event window",
                "Process/service logs from DUT",
                "Re-run with narrowed anomaly categories to isolate root cause"
            ],
            "repro_hint": "Use the same engine/seed set and throttle, test against the same service & port."
        }
    }
    with open(os.path.join(outdir, "evidence_summary.json"), "w") as fh:
        json.dump(summary, fh, indent=2)

    print("[evidence] Collected at", outdir)

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: collect_evidence.py <run_id> [destdir]")
        raise SystemExit(2)
    collect(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
