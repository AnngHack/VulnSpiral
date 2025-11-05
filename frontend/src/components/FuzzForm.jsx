import React, { useEffect, useMemo, useState } from "react";
import axios from "axios";

export default function FuzzForm({
  runId,
  onStarted,
  onRunCleared,
  ip,
  setIp,
  port,
  setPort,
  transport,          // controlled by App
  setTransport,       // controlled by App
  seedVersion
}) {
  const [interfaces, setInterfaces] = useState([]);
  const [iface, setIface] = useState("wlan0");
  const [engine, setEngine] = useState("radamsa");
  const [duration, setDuration] = useState(30);
  const [throttleMs, setThrottleMs] = useState(5);
  const [confirmRemote, setConfirmRemote] = useState(true);
  const [proxyBindPort, setProxyBindPort] = useState(8888);

  const [seedOptions, setSeedOptions] = useState([]);
  const [selectedSeeds, setSelectedSeeds] = useState([]);

  useEffect(() => {
    axios.get("/api/interfaces").then(r => setInterfaces(r.data.interfaces || []));
  }, []);

  useEffect(() => {
    const load = async () => {
      const r = await axios.get("/api/seeds");
      const seeds = r.data.seeds || [];
      setSeedOptions(seeds);
      if (!selectedSeeds.length && seeds.length) {
        setSelectedSeeds([seeds[0].path]);
      }
    };
    load();
  }, [seedVersion]);

  const selectedDescriptions = useMemo(() => {
    const m = new Map(seedOptions.map(s => [s.path, s]));
    return selectedSeeds.map(p => m.get(p)?.description || p);
  }, [selectedSeeds, seedOptions]);

  const start = async () => {
    if (!ip || !port || !iface) {
      alert("Please set IP, Port and Interface.");
      return;
    }
    if (!confirm("Start fuzzing this DUT? Ensure you have permission.")) return;

    const payload = {
      target_ip: ip,
      target_port: parseInt(port, 10),
      transport,   // from props
      interface: iface,
      duration_seconds: parseInt(duration, 10),
      engine,
      seed_files: selectedSeeds,
      extra_opts: {
        confirm_remote: confirmRemote,
        throttle_ms: parseInt(throttleMs, 10) || 0,
        ...(engine === "proxy" ? { proxy_bind_port: parseInt(proxyBindPort, 10) || 8888 } : {}),
        anomaly_profile: {
          size_overflow: 50,
          boundary_values: 30,
          null_bytes: 30,
          random_noise: 20,
          special_chars: 10,
          format_strings: 5,
          invalid_utf8: 5
        }
      }
    };

    const r = await axios.post("/api/fuzz/start", payload);
    const id = r.data.run_id;
    if (onStarted) onStarted(id);
    alert("Started run: " + id);
  };

  const stopCurrent = async () => {
    if (!runId) return;
    await axios.post("/api/fuzz/stop", { run_id: runId });
    alert("Stopping run: " + runId);
  };

  const stopAll = async () => {
    const r = await axios.post("/api/fuzz/stop_all");
    alert("Stopping all runs: " + (r.data.stopped || []).join(", "));
    if (onRunCleared) onRunCleared();
  };

  const downloadPcap = () => {
    if (!runId) return;
    window.open(`/api/fuzz/pcap/${runId}`, "_blank");
  };

  return (
    <div className="card p-3">
      <h5>Fuzz target</h5>
      <div className="row">
        <div className="col-7 mb-2">
          <label className="form-label">Target IP</label>
          <input className="form-control" value={ip} onChange={e=>setIp(e.target.value)} />
        </div>
        <div className="col-5 mb-2">
          <label className="form-label">Port</label>
          <input type="number" className="form-control" value={port} onChange={e=>setPort(e.target.value)} />
        </div>
      </div>

      <div className="row">
        <div className="col-4 mb-2">
          <label className="form-label">Transport</label>
          <select className="form-select" value={transport} onChange={e=>setTransport(e.target.value)}>
            <option value="tcp">TCP</option>
            <option value="udp">UDP</option>
          </select>
        </div>
        <div className="col-4 mb-2">
          <label className="form-label">Interface</label>
          <select className="form-select" value={iface} onChange={e=>setIface(e.target.value)}>
            {interfaces.map(i => <option key={i} value={i}>{i}</option>)}
          </select>
        </div>
        <div className="col-4 mb-2">
          <label className="form-label">Engine</label>
          <select className="form-select" value={engine} onChange={e=>setEngine(e.target.value)}>
            <option value="radamsa">radamsa</option>
            <option value="boofuzz">boofuzz</option>
            <option value="custom">custom</option>
            <option value="proxy">proxy</option>
          </select>
        </div>
      </div>

      {engine === "proxy" && (
        <div className="mb-2">
          <label className="form-label">Proxy bind port (local)</label>
          <input type="number" className="form-control" value={proxyBindPort} onChange={e=>setProxyBindPort(e.target.value)} />
          <small className="text-muted">Point your client to 127.0.0.1:{proxyBindPort} → DUT</small>
        </div>
      )}

      <div className="row">
        <div className="col-6 mb-2">
          <label className="form-label">Duration (seconds)</label>
          <input type="number" className="form-control" value={duration} onChange={e=>setDuration(e.target.value)} />
          <small className="text-muted">0 = run until stop</small>
        </div>
        <div className="col-6 mb-2">
          <label className="form-label">Throttle (ms)</label>
          <input type="number" className="form-control" value={throttleMs} onChange={e=>setThrottleMs(e.target.value)} />
          <small className="text-muted">0 = max rate</small>
        </div>
      </div>

      {/* Seeds select (multi) */}
      <div className="mb-2">
        <label className="form-label">Seeds (multi-select)</label>
        <select
          className="form-select"
          multiple
          value={selectedSeeds}
          onChange={e => {
            const vals = Array.from(e.target.selectedOptions).map(o => o.value);
            setSelectedSeeds(vals);
          }}
          size={Math.min(5, Math.max(3, seedOptions.length))}
        >
          {seedOptions.map(s => (
            <option key={s.path} value={s.path} title={s.description}>{s.name} — {s.path}</option>
          ))}
        </select>
        {selectedSeeds.length > 0 && (
          <div className="form-text mt-1">
            <ul className="mb-0">
              {selectedDescriptions.map((d, idx) => <li key={idx}>{d}</li>)}
            </ul>
          </div>
        )}
      </div>

      {/* Controls */}
      <div className="d-flex flex-wrap gap-2 mt-2">
        <button className="btn btn-danger" onClick={start}>Start fuzz</button>
        <button className="btn btn-secondary" onClick={stopCurrent} disabled={!runId}>Stop current</button>
        <button className="btn btn-outline-secondary" onClick={stopAll}>Stop all</button>
        <button className="btn btn-outline-primary" onClick={downloadPcap} disabled={!runId}>Download PCAP</button>
      </div>
    </div>
  );
}
