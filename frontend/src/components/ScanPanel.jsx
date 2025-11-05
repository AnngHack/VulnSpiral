import React, { useEffect, useState } from "react";
import axios from "axios";

const PRESETS_TCP = [
  { key: "top1000", label: "Top 1000 (nmap)", hint: "nmap --top-ports 1000" },
  { key: "recommended", label: "Recommended (CPE)", ports: "22,53,80,443,8080,8443,7547,5000,49152-49157" },
  { key: "all", label: "All (1-65535)", ports: "1-65535" },
  { key: "custom", label: "Custom", ports: "" },
];

const PRESETS_UDP = [
  { key: "top1000", label: "Top 1000 (nmap)", hint: "nmap --top-ports 1000" },
  { key: "recommended", label: "Recommended (CPE)", ports: "53,67,68,69,123,161,162,1900,3702,5353" },
  { key: "all", label: "All (1-65535)", ports: "1-65535" },
  { key: "custom", label: "Custom", ports: "" },
];

export default function ScanPanel({ ip, setIp, setPort, setTransport, onSeedsChanged, onScanStarted }) {
  const [scanIp, setScanIp] = useState(ip);
  useEffect(() => setScanIp(ip), [ip]);

  const [useNmap, setUseNmap] = useState(true);
  const [tcpPreset, setTcpPreset] = useState("top1000");
  const [udpPreset, setUdpPreset] = useState("recommended");
  const [tcpPorts, setTcpPorts] = useState("");
  const [udpPorts, setUdpPorts] = useState("");

  const [scanTCP, setScanTCP] = useState(true);
  const [scanUDP, setScanUDP] = useState(false);
  const [results, setResults] = useState({ tcp_open: [], udp_maybe_open: [], method: "" });

  const [seeds, setSeeds] = useState([]);
  const [genKind, setGenKind] = useState("http");
  const [genName, setGenName] = useState("");
  const [genDesc, setGenDesc] = useState("");
  const [genHost, setGenHost] = useState("dut");
  const [genQName, setGenQName] = useState("example.com");
  const [genHex, setGenHex] = useState("");

  const [scanId, setScanId] = useState(null);
  const [scanning, setScanning] = useState(false);

  const refreshSeeds = async () => {
    const r = await axios.get("/api/seeds");
    setSeeds(r.data.seeds || []);
    if (onSeedsChanged) onSeedsChanged();
  };
  useEffect(() => { refreshSeeds(); }, []);

  const startScan = async () => {
    const method = useNmap ? "nmap" : "auto";
    let ports = "";
    let top_ports = null;

    if (scanTCP && tcpPreset === "top1000" && useNmap) top_ports = 1000;
    else if (scanTCP) ports = tcpPreset === "custom" ? tcpPorts : PRESETS_TCP.find(p => p.key === tcpPreset)?.ports || "";

    if (scanUDP && udpPreset === "top1000" && useNmap) top_ports = 1000;
    else if (scanUDP) ports = ports || (udpPreset === "custom" ? udpPorts : PRESETS_UDP.find(p => p.key === udpPreset)?.ports || "");

    const form = new FormData();
    form.append("ip", scanIp);
    form.append("method", method);
    form.append("tcp", scanTCP ? "1" : "0");
    form.append("udp", scanUDP ? "1" : "0");
    if (ports) form.append("ports", ports);
    if (top_ports) form.append("top_ports", String(top_ports));
    form.append("timeout_ms", "300");

    const r = await axios.post("/api/ports/scan/start", form);
    setScanId(r.data.scan_id);
    setScanning(true);
    if (onScanStarted) onScanStarted(r.data.scan_id);
  };

  const stopScan = async () => {
    if (!scanId) return;
    await axios.post("/api/ports/scan/stop", { scan_id: scanId });
    setScanning(false);
  };

  const refreshResults = async () => {
    if (!scanId) return;
    const r = await axios.get(`/api/ports/scan/result/${scanId}`);
    setResults(r.data.result || { tcp_open: [], udp_maybe_open: [], method: "" });
    setScanning(false);
  };

  // APPLY PORT NOW ALSO SETS TRANSPORT
  const applyPort = (p, proto) => {
    setIp(scanIp);
    setPort(p);
    setTransport(proto);  // <— fix: select TCP/UDP in fuzz form
  };

  const deleteSeed = async (s) => {
    const base = s.path.split("/").pop();
    if (!confirm(`Delete seed ${base}?`)) return;
    await axios.delete(`/api/seeds/${encodeURIComponent(base)}`);
    await refreshSeeds();
  };

  const generateSeed = async () => {
    const body = {
      kind: genKind,
      name: genName || undefined,
      description: genDesc || undefined,
      host: genHost || undefined,
      qname: genQName || undefined,
      payload_hex: genKind === "custom" && genHex ? genHex : undefined
    };
    const r = await axios.post("/api/seeds/generate", body);
    await refreshSeeds();
    alert(`Seed generated: ${r.data.seed.name}`);
    setGenName(""); setGenDesc(""); setGenHex("");
  };

  return (
    <div className="card p-3">
      <h5>Scan & Seeds</h5>

      {/* Target for scan */}
      <div className="row">
        <div className="col-8 mb-2">
          <label className="form-label">Target IP for scan</label>
          <input className="form-control" value={scanIp} onChange={e=>setScanIp(e.target.value)} />
          <small className="text-muted">Click a discovered port to use it and set transport automatically.</small>
        </div>
        <div className="col-4 mb-2">
          <label className="form-label">Scanner</label>
          <select className="form-select" value={useNmap ? "nmap" : "auto"} onChange={e=>setUseNmap(e.target.value==="nmap")}>
            <option value="nmap">nmap (no ping)</option>
            <option value="auto">builtin (fast)</option>
          </select>
        </div>
      </div>

      {/* Presets */}
      <div className="row">
        <div className="col-6 mb-2">
          <label className="form-label">TCP Preset</label>
          <select className="form-select" value={tcpPreset} onChange={e=>setTcpPreset(e.target.value)}>
            {PRESETS_TCP.map(p => <option key={p.key} value={p.key}>{p.label}</option>)}
          </select>
          {tcpPreset === "custom" && (
            <input className="form-control mt-2" placeholder="e.g., 1-1024,22,80,443" value={tcpPorts} onChange={e=>setTcpPorts(e.target.value)} />
          )}
          <div className="form-check mt-2">
            <input className="form-check-input" type="checkbox" id="tcpScan" checked={scanTCP} onChange={e=>setScanTCP(e.target.checked)} />
            <label className="form-check-label" htmlFor="tcpScan">Scan TCP</label>
          </div>
        </div>
        <div className="col-6 mb-2">
          <label className="form-label">UDP Preset</label>
          <select className="form-select" value={udpPreset} onChange={e=>setUdpPreset(e.target.value)}>
            {PRESETS_UDP.map(p => <option key={p.key} value={p.key}>{p.label}</option>)}
          </select>
          {udpPreset === "custom" && (
            <input className="form-control mt-2" placeholder="e.g., 53,67,68,69,123" value={udpPorts} onChange={e=>setUdpPorts(e.target.value)} />
          )}
          <div className="form-check mt-2">
            <input className="form-check-input" type="checkbox" id="udpScan" checked={scanUDP} onChange={e=>setScanUDP(e.target.checked)} />
            <label className="form-check-label" htmlFor="udpScan">Scan UDP</label>
          </div>
        </div>
      </div>

      <div className="d-flex gap-2 mb-2">
        {!scanning ? (
          <button className="btn btn-outline-dark" onClick={startScan}>Start scan</button>
        ) : (
          <button className="btn btn-outline-secondary" onClick={stopScan}>Stop scan</button>
        )}
        <button className="btn btn-outline-primary" onClick={refreshResults} disabled={!scanId}>Load results</button>
      </div>

      {/* Results */}
      {(results.tcp_open?.length || results.udp_maybe_open?.length) ? (
        <div className="mt-2">
          <div><strong>TCP open:</strong> {results.tcp_open.join(", ") || "none"}</div>
          <div className="d-flex flex-wrap gap-2 mt-2">
            {results.tcp_open.map(p => (
              <button key={`t${p}`} className="btn btn-sm btn-outline-primary" onClick={() => applyPort(p, "tcp")}>
                Use TCP {p}
              </button>
            ))}
          </div>
          <div className="mt-3"><strong>UDP maybe open:</strong> {results.udp_maybe_open.join(", ") || "none"}</div>
          <div className="d-flex flex-wrap gap-2 mt-2">
            {results.udp_maybe_open.map(p => (
              <button key={`u${p}`} className="btn btn-sm btn-outline-primary" onClick={() => applyPort(p, "udp")}>
                Use UDP {p}
              </button>
            ))}
          </div>
        </div>
      ) : (
        <div className="form-text mt-1">No results yet. Start a scan to discover ports on {scanIp}.</div>
      )}

      <hr className="my-3" />

      {/* Seed generation */}
      <h6>Generate a seed (no CLI needed)</h6>
      <div className="row">
        <div className="col-md-3 mb-2">
          <label className="form-label">Kind</label>
          <select className="form-select" value={genKind} onChange={e=>setGenKind(e.target.value)}>
            <option value="http">HTTP (TCP)</option>
            <option value="dns">DNS query (UDP)</option>
            <option value="ssh">SSH banner (TCP)</option>
            <option value="custom">Custom (binary)</option>
          </select>
        </div>
        <div className="col-md-5 mb-2">
          <label className="form-label">Name (optional)</label>
          <input className="form-control" value={genName} onChange={e=>setGenName(e.target.value)} />
        </div>
        <div className="col-md-4 mb-2">
          <label className="form-label">Description (optional)</label>
          <input className="form-control" value={genDesc} onChange={e=>setGenDesc(e.target.value)} />
        </div>
      </div>

      {genKind === "http" && (
        <div className="mb-2">
          <label className="form-label">HTTP Host header</label>
          <input className="form-control" value={genHost} onChange={e=>setGenHost(e.target.value)} />
          <small className="text-muted">Example: {ip}</small>
        </div>
      )}
      {genKind === "dns" && (
        <div className="mb-2">
          <label className="form-label">DNS qname</label>
          <input className="form-control" value={genQName} onChange={e=>setGenQName(e.target.value)} />
          <small className="text-muted">Example: example.com</small>
        </div>
      )}
      {genKind === "custom" && (
        <div className="mb-2">
          <label className="form-label">Payload (hex, optional)</label>
          <input className="form-control" placeholder="e.g., deadbeef00ff" value={genHex} onChange={e=>setGenHex(e.target.value)} />
          <small className="text-muted">Leave empty to auto-generate binary pattern.</small>
        </div>
      )}

      <div className="d-flex gap-2">
        <button className="btn btn-outline-primary" onClick={generateSeed}>Generate seed</button>
        <button className="btn btn-outline-secondary" onClick={refreshSeeds}>Refresh list</button>
      </div>

      {/* Seeds list with delete */}
      <div className="mt-3">
        <strong>Available seeds</strong>
        {seeds.length === 0 ? (
          <div className="form-text">No seeds yet. Generate or upload one.</div>
        ) : (
          <ul className="small mb-0">
            {seeds.map(s => (
              <li key={s.path} title={s.description}>
                {s.name} <code>{s.path}</code> ({s.size} bytes)
                <button className="btn btn-sm btn-outline-danger ms-2" onClick={() => deleteSeed(s)}>Delete</button>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
