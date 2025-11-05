import React, { useEffect, useRef, useState } from "react";

export default function ScanLogViewer({ scanId }) {
  const [lines, setLines] = useState([]);
  const wsRef = useRef(null);
  const listRef = useRef(null);

  useEffect(() => {
    setLines([]);
    if (!scanId) return;

    const proto = window.location.protocol === "https:" ? "wss" : "ws";
    const url = `${proto}://${window.location.host}/ws/scan/${scanId}`;
    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data);
        const ts = new Date().toLocaleTimeString();
        if (msg.type === "finished") {
          setLines((prev) => [...prev, `[${ts}] scan finished: open TCP=${(msg.result?.tcp_open||[]).length}, UDP maybe=${(msg.result?.udp_maybe_open||[]).length}`]);
        } else if (msg.type === "progress" || msg.type === "info" || msg.type === "error") {
          setLines((prev) => [...prev, `[${ts}] ${msg.message}`]);
        } else {
          setLines((prev) => [...prev, `[${ts}] ${ev.data}`]);
        }
      } catch {
        setLines((prev) => [...prev, ev.data]);
      }
      if (listRef.current) listRef.current.scrollTop = listRef.current.scrollHeight;
    };

    ws.onclose = () => {
      wsRef.current = null;
    };

    return () => {
      try { ws.close(); } catch (_) {}
    };
  }, [scanId]);

  return (
    <div style={{height: 220, overflow: "auto", fontFamily: "monospace", fontSize: 12}} ref={listRef}>
      {scanId ? (
        lines.length ? lines.map((l, i) => <div key={i}>{l}</div>) : <div className="text-muted">Waiting for scan output...</div>
      ) : (
        <div className="text-muted">No scan active.</div>
      )}
    </div>
  );
}
