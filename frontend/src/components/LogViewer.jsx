import React, { useEffect, useRef, useState } from "react";

export default function LogViewer({ runId }) {
  const [lines, setLines] = useState([]);
  const wsRef = useRef(null);
  const boxRef = useRef(null);

  useEffect(() => {
    if (!runId) {
      setLines(["(no run started)"]);
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
      return;
    }

    setLines(prev => [...prev, `connecting to /ws/logs/${runId} ...`]);
    const ws = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/ws/logs/${runId}`);
    wsRef.current = ws;

    ws.onopen = () => setLines(prev => [...prev, "[connected]"]);
    ws.onclose = () => setLines(prev => [...prev, "[disconnected]"]);
    ws.onerror = () => setLines(prev => [...prev, "[error]"]);

    ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data);
        if (msg.type === "heartbeat") {
          setLines(prev => [...prev, `heartbeat: sent=${msg.sent} errors=${msg.errors}`]);
        } else if (msg.type === "finished") {
          setLines(prev => [...prev, `finished: pcap=${msg.pcap || "n/a"}`]);
        } else if (msg.type === "error") {
          setLines(prev => [...prev, `error: ${msg.message}`]);
        } else {
          setLines(prev => [...prev, JSON.stringify(msg)]);
        }
      } catch (e) {
        setLines(prev => [...prev, ev.data]);
      }
    };

    return () => {
      try { ws.close(); } catch {}
      wsRef.current = null;
    };
  }, [runId]);

  useEffect(() => {
    if (boxRef.current) {
      boxRef.current.scrollTop = boxRef.current.scrollHeight;
    }
  }, [lines]);

  return (
    <div ref={boxRef} style={{ height: 240, overflowY: "auto", fontFamily: "monospace", fontSize: "0.85rem", whiteSpace: "pre-wrap" }}>
      {lines.map((l, i) => <div key={i}>{l}</div>)}
    </div>
  );
}
