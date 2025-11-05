# Inline mutating proxy (client/server/peer/proxy mode).
# Listens locally and forwards to DUT while applying anomaly transforms.
# Configure via extra_opts:
#   - proxy_bind_host (default "0.0.0.0")
#   - proxy_bind_port (required)
#   - throttle_ms (int)
#   - anomaly_profile (dict category->weight)

import asyncio
import socket
import random

class ProxyEngine:
    def __init__(self, ctx, pcap_helper):
        self.ctx = ctx
        self.pcap_helper = pcap_helper
        self._task = None
        self._running = False

    async def start(self):
        host, port = self.ctx.cfg["target"].rsplit(":", 1)
        port = int(port)
        transport = self.ctx.cfg.get("transport", "tcp")
        opts = self.ctx.cfg.get("extra_opts", {})
        bind_host = opts.get("proxy_bind_host", "0.0.0.0")
        bind_port = int(opts.get("proxy_bind_port", 8888))

        self.ctx.logger.info(f"[proxy] {transport} listening on {bind_host}:{bind_port} → {host}:{port}")
        self._running = True
        if transport == "tcp":
            self._task = asyncio.create_task(self._run_tcp_proxy(bind_host, bind_port, host, port))
        else:
            self._task = asyncio.create_task(self._run_udp_proxy(bind_host, bind_port, host, port))

    async def stop(self):
        self._running = False
        if self._task:
            try:
                await asyncio.wait_for(self._task, timeout=5)
            except Exception:
                pass
        self.ctx.logger.info("[proxy] stopped")

    # ---------------- TCP -----------------
    async def _run_tcp_proxy(self, bind_host, bind_port, dst_host, dst_port):
        server = await asyncio.start_server(
            lambda r, w: self._handle_tcp_client(r, w, dst_host, dst_port),
            host=bind_host, port=bind_port
        )
        async with server:
            await server.serve_forever()

    async def _handle_tcp_client(self, reader, writer, dst_host, dst_port):
        try:
            r2, w2 = await asyncio.open_connection(dst_host, dst_port)
        except Exception as e:
            self.ctx.logger.warning(f"[proxy] connect to DUT failed: {e}")
            writer.close()
            return

        async def pump(src_reader, dst_writer, direction):
            # direction: "cs" (client->server) or "sc" (server->client)
            opts = self.ctx.cfg.get("extra_opts", {})
            throttle_ms = int(opts.get("throttle_ms", 0))
            while self._running:
                try:
                    data = await src_reader.read(4096)
                    if not data:
                        break
                    data2 = self._apply_anomaly(data, direction)
                    dst_writer.write(data2)
                    await dst_writer.drain()
                    self.ctx.sent += 1
                    self.ctx.logger.info(f"[proxy] {direction} len={len(data2)}")
                    # Evidence: write both directions
                    self.pcap_helper.write_raw(data2, dst_host, dst_port, "tcp")
                    if throttle_ms > 0:
                        await asyncio.sleep(throttle_ms / 1000.0)
                except Exception as e:
                    self.ctx.errors += 1
                    self.ctx.logger.warning(f"[proxy] pump error: {e}")
                    break

        dst_host = dst_host  # for closure
        dst_port = dst_port

        t1 = asyncio.create_task(pump(reader, w2, "cs"))
        t2 = asyncio.create_task(pump(r2, writer, "sc"))
        await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)
        try:
            writer.close(); await writer.wait_closed()
        except Exception:
            pass
        try:
            w2.close(); await w2.wait_closed()
        except Exception:
            pass

    # ---------------- UDP -----------------
    async def _run_udp_proxy(self, bind_host, bind_port, dst_host, dst_port):
        loop = asyncio.get_event_loop()
        cs_map = {}  # (client_addr) -> (last_seen)

        def sendto(sock, data, addr):
            try:
                sock.sendto(data, addr)
            except Exception:
                pass

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s_in, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s_out:
            s_in.bind((bind_host, bind_port))
            s_in.setblocking(False)
            s_out.setblocking(False)

            self.ctx.logger.info(f"[proxy-udp] listening {bind_host}:{bind_port} → {dst_host}:{dst_port}")

            while self._running:
                try:
                    data, addr = await loop.run_in_executor(None, s_in.recvfrom, 65535)
                except Exception:
                    await asyncio.sleep(0.01)
                    continue
                cs_map[addr] = True
                data2 = self._apply_anomaly(data, "cs")
                sendto(s_out, data2, (dst_host, dst_port))
                self.pcap_helper.write_raw(data2, dst_host, dst_port, "udp")
                self.ctx.sent += 1

                # try read response (best-effort)
                try:
                    s_out.settimeout(0.001)
                    resp, raddr = s_out.recvfrom(65535)
                    resp2 = self._apply_anomaly(resp, "sc")
                    sendto(s_in, resp2, addr)
                    self.pcap_helper.write_raw(resp2, addr[0], addr[1], "udp")
                except Exception:
                    pass

    # -------------- Anomalies --------------
    def _apply_anomaly(self, data: bytes, direction: str) -> bytes:
        """
        Anomaly profiling: emphasize categories by weights in extra_opts.anomaly_profile.
        Categories: size_overflow, boundary_values, invalid_utf8, special_chars,
                    format_strings, null_bytes, random_noise
        """
        opts = self.ctx.cfg.get("extra_opts", {})
        profile = opts.get("anomaly_profile", {}) or {}
        total = sum(int(profile.get(k, 0)) for k in profile.keys()) or 0
        if total <= 0:
            return data
        # Weighted pick
        r = random.randint(1, total)
        cum = 0
        pick = None
        for k, w in profile.items():
            w = int(w); 
            if w <= 0: 
                continue
            cum += w
            if r <= cum:
                pick = k; break
        if not pick:
            return data

        # transforms
        try:
            if pick == "size_overflow":
                return (data * 8)[:8192] + b"A" * 1024
            if pick == "boundary_values":
                return b"\x00" * 1 + data + b"\xff" * 1
            if pick == "invalid_utf8":
                return data + b"\xc3\x28\xed\xa0\x80"  # invalid sequences
            if pick == "special_chars":
                return data + b"\r\n\r\n" + b"\x7f" * 8
            if pick == "format_strings":
                return data + b"%n%n%n%p%x%x%x"
            if pick == "null_bytes":
                return data + (b"\x00" * 256)
            if pick == "random_noise":
                return data + bytes(random.getrandbits(8) for _ in range(512))
        except Exception:
            return data
        return data
