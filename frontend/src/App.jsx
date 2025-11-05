import React, { useState } from "react";
import FuzzForm from "./components/FuzzForm.jsx";
import ScanPanel from "./components/ScanPanel.jsx";
import LogViewer from "./components/LogViewer.jsx";
import ScanLogViewer from "./components/ScanLogViewer.jsx";
import PcapManager from "./components/PcapManager.jsx";
import StatusBadge from "./components/StatusBadge.jsx";
import "./styles.css";

export default function App() {
  const [runId, setRunId] = useState(null);
  const [scanId, setScanId] = useState(null);

  const [ip, setIp] = useState("192.168.8.1");
  const [port, setPort] = useState(80);
  const [transport, setTransport] = useState("tcp"); // LIFTED to App

  const [seedVersion, setSeedVersion] = useState(0);

  return (
    <div className="container py-3">
      <div className="d-flex align-items-center justify-content-between mb-2">
        <h1 className="mb-0">VulnSpiral</h1>
        <div className="d-flex gap-2">
          {/* CHANGED: point to /ui/help instead of /ui/help.html */}
          <a className="btn btn-outline-info btn-sm" href="/help" target="_blank" rel="noreferrer">
            Help
          </a>
          <StatusBadge runId={runId} />
        </div>
      </div>

      {/* Two columns: Fuzz | Scan+Seeds */}
      <div className="row g-3">
        <div className="col-lg-6">
          <FuzzForm
            runId={runId}
            onStarted={(id) => setRunId(id)}
            onRunCleared={() => setRunId(null)}
            ip={ip}
            setIp={setIp}
            port={port}
            setPort={setPort}
            transport={transport}          // pass down
            setTransport={setTransport}    // pass down
            seedVersion={seedVersion}
          />
        </div>
        <div className="col-lg-6">
          <ScanPanel
            ip={ip}
            setIp={setIp}
            setPort={setPort}
            setTransport={setTransport}    // allow Scan to set transport
            onSeedsChanged={() => setSeedVersion((v) => v + 1)}
            onScanStarted={(id) => setScanId(id)}
            onScanFinished={() => {}}
          />
        </div>
      </div>

      {/* Logs: side by side */}
      <div className="row mt-3 g-3">
        <div className="col-lg-6">
          <div className="card p-2">
            <h6 className="mb-2">Fuzz Log {runId ? `(${runId.slice(0,8)})` : ""}</h6>
            <LogViewer runId={runId} />
          </div>
        </div>
        <div className="col-lg-6">
          <div className="card p-2">
            <h6 className="mb-2">Port Scan Log {scanId ? `(${scanId.slice(0,8)})` : ""}</h6>
            <ScanLogViewer scanId={scanId} />
          </div>
        </div>
      </div>

      {/* PCAP Manager */}
      <div className="row mt-3">
        <div className="col-12">
          <PcapManager />
        </div>
      </div>
    </div>
  );
}
