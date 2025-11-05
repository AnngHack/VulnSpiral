# Custom engine: craft IP/TCP or IP/UDP packets with Scapy on a given interface,
# and apply anomaly profiling to payloads.

import asyncio, random
from scapy.all import send, IP, TCP, UDP, Raw

class CustomEngine:
    def __init__(self, ctx, pcap_helper):
        self.ctx = ctx
        self.pcap_helper = pcap_helper
        self.running = False
        self._task = None

    async def start(self):
        self.running = True
        self._task = asyncio.create_task(self._loop())

    def _payload(self, i: int) -> bytes:
        return (b"HELLO-" + bytes([i % 256])) * (1 + (i % 4))

    def _apply_anomaly(self, data: bytes) -> bytes:
        profile = self.ctx.cfg.get("extra_opts", {}).get("anomaly_profile", {}) or {}
        total = sum(int(profile.get(k, 0)) for k in profile.keys()) or 0
        if total <= 0:
            return data
        r = random.randint(1, total)
        cum = 0; pick = None
        for k, w in profile.items():
            w = int(w); 
            if w <= 0: continue
            cum += w
            if r <= cum:
                pick = k; break
        if pick == "size_overflow": return (data * 12)[:16384] + b"A"*2048
        if pick == "boundary_values": return b"\x00"+data+b"\xff"
        if pick == "invalid_utf8": return data + b"\xed\xa0\x80"
        if pick == "special_chars": return data + b"\r\n\r\n" + b"\x1b"*8
        if pick == "format_strings": return data + b"%n%p%x%x"
        if pick == "null_bytes": return data + b"\x00"*512
        if pick == "random_noise": return data + bytes(random.getrandbits(8) for _ in range(1024))
        return data

    async def _loop(self):
        host, port = self.ctx.cfg["target"].rsplit(":", 1)
        port = int(port)
        transport = self.ctx.cfg.get("transport", "tcp")
        iface = self.ctx.cfg.get("interface", "lo")
        throttle_ms = int(self.ctx.cfg.get("extra_opts", {}).get("throttle_ms", 10))
        i = 0
        while self.running and not self.ctx._stop_event.is_set():
            payload = self._apply_anomaly(self._payload(i))
            try:
                if transport == "tcp":
                    pkt = IP(dst=host)/TCP(dport=port)/Raw(load=payload)
                else:
                    pkt = IP(dst=host)/UDP(dport=port)/Raw(load=payload)
                send(pkt, iface=iface, verbose=False)
                self.pcap_helper.write_packet(pkt)
                self.ctx.sent += 1
                self.ctx.logger.info(f"[custom] {transport} len={len(payload)}")
            except Exception as e:
                self.ctx.errors += 1
                self.ctx.logger.warning(f"[custom] send error: {e}")
            i += 1
            if throttle_ms > 0:
                await asyncio.sleep(throttle_ms / 1000.0)
            else:
                await asyncio.sleep(0)

    async def stop(self):
        self.running = False
        if self._task:
            try:
                await asyncio.wait_for(self._task, timeout=5)
            except Exception:
                pass
