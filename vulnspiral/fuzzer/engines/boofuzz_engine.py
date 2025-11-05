# Minimal boofuzz integration placeholder with TCP/UDP fallback if templates not provided.
# Applies anomaly profiling to fallback payloads.

import asyncio, socket, random

try:
    from boofuzz import Session, Target, s_initialize, s_string, s_static, s_delim, s_get
except Exception:
    Session = None

def _apply_anomaly(data: bytes, profile: dict) -> bytes:
    if not profile:
        return data
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
    if pick == "size_overflow": return (data * 8)[:8192] + b"A"*1024
    if pick == "boundary_values": return b"\x00"+data+b"\xff"
    if pick == "invalid_utf8": return data + b"\xc3\x28"
    if pick == "special_chars": return data + b"\r\n\r\n" + b"\x7f"*4
    if pick == "format_strings": return data + b"%n%p%x"
    if pick == "null_bytes": return data + b"\x00"*256
    if pick == "random_noise": return data + bytes(random.getrandbits(8) for _ in range(512))
    return data

class BoofuzzEngine:
    def __init__(self, ctx, pcap_helper):
        self.ctx = ctx
        self.pcap_helper = pcap_helper
        self._running = False
        self._task = None

    async def start(self):
        self._running = True
        self._task = asyncio.create_task(self._loop())

    async def _loop(self):
        host, port = self.ctx.cfg["target"].rsplit(":", 1)
        port = int(port)
        transport = self.ctx.cfg.get("transport", "tcp")
        throttle_ms = int(self.ctx.cfg.get("extra_opts", {}).get("throttle_ms", 10))
        profile = self.ctx.cfg.get("extra_opts", {}).get("anomaly_profile", {}) or {}

        # If boofuzz not available or no template, use a simple mutational fallback
        if Session is None or transport == "udp":
            self.ctx.logger.warning("boofuzz not available or UDP requested; using basic fuzzer")
            i = 0
            while self._running and not self.ctx._stop_event.is_set():
                data = (b"A" * ((i % 1500) + 1)) + bytes([i % 256])
                data = _apply_anomaly(data, profile)
                try:
                    if transport == "tcp":
                        with socket.create_connection((host, port), timeout=2) as s:
                            s.sendall(data)
                    else:
                        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                            s.sendto(data, (host, port))
                    self.ctx.sent += 1
                    self.ctx.logger.info(f"[boofuzz-fallback] {transport} len={len(data)}")
                    self.pcap_helper.write_raw(data, host, port, transport)
                except Exception as e:
                    self.ctx.errors += 1
                    self.ctx.logger.warning(f"[boofuzz-fallback] {transport} error: {e}")
                i += 1
                await asyncio.sleep(max(0, throttle_ms) / 1000.0)
            return

        # Example tiny HTTP grammar for TCP (extend for real protocols)
        s_initialize("http_req")
        s_static("GET")
        s_delim(" ")
        s_string("/", name="path")
        s_delim(" ")
        s_static("HTTP/1.1")
        s_delim("\r\n")
        s_static("Host: ")
        s_string("dut", name="hosthdr")
        s_delim("\r\n\r\n")

        session = Session(target=Target(connection=(host, port)), fuzz_data_logger=None)
        try:
            session.connect(s_get("http_req"))
            end_time = asyncio.get_event_loop().time() + max(1, int(self.ctx.cfg["duration"] or 10))
            while self._running and not self.ctx._stop_event.is_set() and asyncio.get_event_loop().time() < end_time:
                session.fuzz(iteration_steps=1)
                self.ctx.sent += 1
                await asyncio.sleep(0)
        except Exception as e:
            self.ctx.errors += 1
            self.ctx.logger.warning(f"[boofuzz] error: {e}")
        finally:
            try:
                session.stop()
            except Exception:
                pass

    async def stop(self):
        self._running = False
        if self._task:
            try:
                await asyncio.wait_for(self._task, timeout=5)
            except Exception:
                pass
