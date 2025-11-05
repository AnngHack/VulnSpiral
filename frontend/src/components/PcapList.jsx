import React, { useEffect, useState } from "react";
import axios from "axios";

function fmtSize(n) {
  if (n > 1024 * 1024) return (n / (1024 * 1024)).toFixed(1) + " MB";
  if (n > 1024) return (n / 1024).toFixed(1) + " KB";
  return n + " B";
}

function fmtTime(ts) {
  try {
    return new Date(ts * 1000).toLocaleString();
  } catch {
    return String(ts);
  }
}

export default function PcapList() {
  const [pcaps, setPcaps] = useState([]);

  const load = async () => {
    const r = await axios.get("/api/pcaps");
    setPcaps(r.data.pcaps || []);
  };

  useEffect(() => {
    load();
    const iv = setInterval(load, 5000);
    return () => clearInterval(iv);
  }, []);

  const del = async (runId) => {
    if (!confirm(`Delete run ${runId} (pcap + logs)?`)) return;
    await axios.delete(`/api/pcaps/${encodeURIComponent(runId)}`);
    load();
  };

  return (
    <div className="mt-2">
      {pcaps.length === 0 ? (
        <div className="form-text">No PCAPs yet.</div>
      ) : (
        <div className="table-responsive">
          <table className="table table-sm align-middle">
            <thead>
              <tr>
                <th>Run ID</th>
                <th>PCAP</th>
                <th>Size</th>
                <th>Modified</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {pcaps.map((p) => (
                <tr key={`${p.run_id}-${p.filename}`}>
                  <td><code>{p.run_id}</code></td>
                  <td>{p.filename}</td>
                  <td>{fmtSize(p.size)}</td>
                  <td>{fmtTime(p.modified)}</td>
                  <td className="d-flex gap-2">
                    <a className="btn btn-sm btn-outline-primary" href={p.download_url} target="_blank" rel="noreferrer">Download</a>
                    <button className="btn btn-sm btn-outline-danger" onClick={() => del(p.run_id)}>Delete</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
