import React, { useEffect, useState } from "react";

export default function StatusBadge({ runId }) {
  const [sent, setSent] = useState(0);
  const [errors, setErrors] = useState(0);

  useEffect(() => {
    if (!runId) return;
    const proto = window.location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(`${proto}://${window.location.host}/ws/logs/${runId}`);
    ws.onmessage = (ev) => {
      try {
        const json = JSON.parse(ev.data);
        if (json.type === "heartbeat") {
          setSent(json.sent || 0);
          setErrors(json.errors || 0);
        }
      } catch {}
    };
    return () => ws.close();
  }, [runId]);

  return (
    <span className="badge bg-secondary">
      {runId ? `Run: ${runId.slice(0,8)} • sent ${sent} • err ${errors}` : "No active run"}
    </span>
  );
}
