import os
import asyncio
import subprocess
import socket
import shutil
import random

from vulnspiral.utils.netiface import get_iface_ipv4

def _find_radamsa():
    # vendor/bin first
    vb = os.path.join(os.getcwd(), "vendor", "bin", "radamsa")
    if os.path.exists(vb) and os.access(vb, os.X_OK):
        return vb
    # env var
    ev = os.environ.get("VULNSPIRAL_RADAMSA")
    if ev and os.path.exists(ev) and os.access(ev, os.X_OK):
        return ev
    # PATH
    w = shutil.which("radamsa")
    return w

class RadamsaEngine:
    def __init__(self, ctx, pcap_helper):
        self.ctx = ctx
        self.pcap_helper = pcap_helper
        self.running = False
        self._task = None
        self.radamsa_path = _find_radamsa()

    async def start(self):
        self.ctx.logger.info("RadamsaEngine starting")
        if not self.radamsa_path:
            self.ctx.logger.warning("radamsa not found; falling back to simple mutations")
        self.running = True
        self._task = asyncio.create_task(self._loop())

    def _mutate(self, data: bytes, idx: int) -> bytes:
        if self.radamsa_path:
            p = subprocess.Popen([self.radamsa_path], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
            out, _ = p.communicate(input=data)
            return out
        # fallback mutation
        return data + bytes([idx % 256]) + (b"\x00" * (idx % 8))

    def _apply_anomaly(self, data: bytes) -> bytes:
        # apply anomaly_profile weighting (same categories as ProxyEngine)
        profile = self.ctx.cfg.get("extra_opts", {}).get("anomaly_profile", {}) or {}
        total = sum(int(profile.get(k, 0)) for k in profile.keys()) or 0
        if total <= 0:
            return data
        r = random.randint(1, total)
        cum = 0
        pick = None
        for k, w in profile.items():
            w = int(w); 
            if w <= 0: continue
            cum += w
            if r <= cum:
                pick = k; break
        if not pick:
            return data
        try:
            if pick == "size_overflow": return (data * 8)[:8192] + b"A"*1024
            if pick == "boundary_values": return b"\x00" + data + b"\xff"
            if pick == "invalid_utf8": return data + b"\xc3\x28\xed\xa0\x80"
            if pick == "special_chars": return data + b"\r\n\r\n" + b"\x7f"*8
            if pick == "format_strings": return data + b"%n%n%n%p%x%x%x"
            if pick == "null_bytes": return data + b"\x00"*256
            if pick == "random_noise": return data + bytes(random.getrandbits(8) for _ in range(512))
        except Exception:
            return data
        return data

    async def _loop(self):
        host, port = self.ctx.cfg["target"].rsplit(":", 1)
        port = int(port)
        transport = self.ctx.cfg.get("transport", "tcp")
        iface = self.ctx.cfg.get("interface", "lo")
        seed_files = self.ctx.cfg.get("seed_files", []) or []
        throttle_ms = int(self.ctx.cfg.get("extra_opts", {}).get("throttle_ms", 5))
        idx = 0

        # optional source binding
        src_ip = get_iface_ipv4(iface)

        while self.running and not self.ctx._stop_event.is_set():
            data = b"PING"
            if seed_files:
                f = seed_files[idx % len(seed_files)]
                try:
                    with open(f, "rb") as fh:
                        data = fh.read()
                except Exception:
                    pass

            mutated = self._mutate(data, idx)
            mutated = self._apply_anomaly(mutated)

            try:
                if transport == "tcp":
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        try:
                            s.setsockopt(socket.SOL_SOCKET, 25, iface.encode())  # SO_BINDTODEVICE
                        except Exception:
                            if src_ip:
                                try: s.bind((src_ip, 0))
                                except Exception: pass
                        s.settimeout(3.0)
                        s.connect((host, port))
                        s.sendall(mutated)
                        try:
                            _ = s.recv(4096)
                        except Exception:
                            pass
                else:  # UDP
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                        try:
                            s.setsockopt(socket.SOL_SOCKET, 25, iface.encode())
                        except Exception:
                            if src_ip:
                                try: s.bind((src_ip, 0))
                                except Exception: pass
                        s.sendto(mutated, (host, port))
                self.ctx.sent += 1
                self.ctx.logger.info(f"[radamsa] {transport} sent len={len(mutated)}")
                self.pcap_helper.write_raw(mutated, host, port, transport)
            except Exception as e:
                self.ctx.errors += 1
                self.ctx.logger.warning(f"[radamsa] send error: {e}")
                await asyncio.sleep(0.5)

            idx += 1
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
        self.ctx.logger.info("RadamsaEngine stopped")
