import React, { useEffect, useState } from "react";
import axios from "axios";

function fmtBytes(b) {
  if (b < 1024) return `${b} B`;
  if (b < 1024*1024) return `${(b/1024).toFixed(1)} KB`;
  return `${(b/1024/1024).toFixed(2)} MB`;
}

export default function PcapManager() {
  const [rows, setRows] = useState([]);

  const refresh = async () => {
    const r = await axios.get("/api/pcaps");
    setRows(r.data.pcaps || []);
  };

  useEffect(() => { refresh(); }, []);

  const download = (runId) => {
    window.open(`/api/fuzz/pcap/${runId}`, "_blank");
  };

  const deleteRun = async (runId) => {
    if (!confirm(`Delete run ${runId} and its PCAP?`)) return;
    await axios.delete(`/api/runs/${encodeURIComponent(runId)}`);
    await refresh();
  };

  return (
    <div className="card p-3">
      <div className="d-flex align-items-center justify-content-between">
        <h5 className="mb-0">PCAPs</h5>
        <button className="btn btn-sm btn-outline-secondary" onClick={refresh}>Refresh</button>
      </div>
      {rows.length === 0 ? (
        <div className="form-text mt-2">No PCAPs yet. Start a fuzz run.</div>
      ) : (
        <div className="table-responsive mt-2">
          <table className="table table-sm align-middle">
            <thead>
              <tr>
                <th>Run</th>
                <th>Target</th>
                <th>Engine</th>
                <th>Transport</th>
                <th>Size</th>
                <th>Modified</th>
                <th style={{width: 180}}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {rows.map(r => (
                <tr key={r.run_id}>
                  <td><code>{r.run_id.slice(0,8)}</code></td>
                  <td>{r.target || "-"}</td>
                  <td>{r.engine || "-"}</td>
                  <td>{r.transport || "-"}</td>
                  <td>{fmtBytes(r.size)}</td>
                  <td>{new Date(r.modified*1000).toLocaleString()}</td>
                  <td>
                    <div className="d-flex gap-2">
                      <button className="btn btn-sm btn-outline-primary" onClick={() => download(r.run_id)}>Download</button>
                      <button className="btn btn-sm btn-outline-danger" onClick={() => deleteRun(r.run_id)}>Delete</button>
                    </div>
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
