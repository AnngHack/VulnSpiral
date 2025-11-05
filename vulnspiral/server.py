# vulnspiral/server.py
"""
VulnSpiral FastAPI backend

- REST API under /api/*
- WebSocket logs:
    - /ws/logs/{run_id}   (fuzz run)
    - /ws/scan/{scan_id}  (port scan job)
- Optional JWT auth via env VULNSPIRAL_JWT_SECRET
- Optional static UI mount at /ui (serve frontend/dist when built)

Updates (0.1.5):
- Seeds CRUD + generator:
    GET/POST/DELETE /api/seeds
    POST /api/seeds/generate
- Port scan jobs with live logs & stop:
    POST /api/ports/scan/start
    POST /api/ports/scan/stop
    GET  /api/ports/scan/result/{scan_id}
    WS   /ws/scan/{scan_id}
    (legacy GET /api/ports/scan kept for quick scans)
- PCAP browser:
    GET    /api/pcaps         (list)
    DELETE /api/runs/{run_id} (delete run folder, including pcap)
- Multi-run plan, stop_all, PCAP download unchanged.
"""

import os
import re
import ipaddress
import asyncio
import time
import shutil
import struct
import random
import uuid
import subprocess
import xml.etree.ElementTree as ET
from typing import List, Optional, Dict, Any, Literal, Set

from fastapi import (
    FastAPI,
    WebSocket,
    WebSocketDisconnect,
    HTTPException,
    Depends,
    Request,
    UploadFile,
    File,
    Form,
    Query,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

import jwt  # pyjwt

from vulnspiral.fuzzer.manager import FuzzManager
from vulnspiral.utils.netiface import list_interfaces

# ------------------------------------------------------------------------------
# App setup
# ------------------------------------------------------------------------------
app = FastAPI(title="VulnSpiral API", version="0.1.5")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Lab/dev; restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

manager = FuzzManager()

# ------------------------------------------------------------------------------
# Optional UI mount
# ------------------------------------------------------------------------------
from fastapi.responses import Response

_UI_BASE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend"))
_UI_DIST = os.path.join(_UI_BASE, "dist")
_UI_PUBLIC = os.path.join(_UI_BASE, "public")

def _help_file_path() -> str | None:
    # Prefer built file in dist/, otherwise source in public/
    p1 = os.path.join(_UI_DIST, "help.html")
    p2 = os.path.join(_UI_PUBLIC, "help.html")
    if os.path.isfile(p1):
        return p1
    if os.path.isfile(p2):
        return p2
    return None

# Serve the built React app (if present) at /ui
if os.path.isdir(_UI_DIST):
    app.mount("/ui", StaticFiles(directory=_UI_DIST, html=True), name="ui")

    @app.get("/", include_in_schema=False)
    async def _root_redirect():
        return RedirectResponse(url="/ui/")
else:
    @app.get("/", include_in_schema=False)
    async def _root_info():
        return JSONResponse(
            {"ok": True, "message": "VulnSpiral API running. Build the frontend and it will be served at /ui.", "docs": "/docs", "ui_built": False}
        )

# Always-available Help at top-level, independent of /ui mount
@app.get("/help", include_in_schema=False)
@app.get("/help.html", include_in_schema=False)
async def help_top():
    hp = _help_file_path()
    if not hp:
        return Response("<html><body><h1>Help</h1><p>Help file not found. Ensure frontend/public/help.html exists or rebuild the UI.</p></body></html>",
                        media_type="text/html")
    return FileResponse(hp, media_type="text/html")

# Convenience redirect so /ui/help works too
@app.get("/ui/help", include_in_schema=False)
@app.get("/ui/help.html", include_in_schema=False)
async def help_under_ui():
    return RedirectResponse(url="/help")
    
# ------------------------------------------------------------------------------
# Auth (optional)
# ------------------------------------------------------------------------------
JWT_SECRET = os.environ.get("VULNSPIRAL_JWT_SECRET", "").strip()
JWT_ALG = "HS256"


async def auth_dep(request: Request) -> Dict[str, Any]:
    if not JWT_SECRET:
        return {"sub": "anon"}
    auth = request.headers.get("authorization") or request.headers.get("Authorization")
    if not auth or not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    token = auth.split(" ", 1)[1].strip()
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        return payload
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")


# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------
def _is_remote_target(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
        return not (ip.is_loopback or ip.is_private)
    except ValueError:
        return host not in ("localhost",)


def _seed_dir() -> str:
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "examples", "seed_samples"))


def _seed_manifest_path() -> str:
    return os.path.join(_seed_dir(), "seeds.json")


def _safe_basename(name: str) -> str:
    base = os.path.basename(name)
    base = re.sub(r"[^A-Za-z0-9._-]+", "_", base)
    return base


def _parse_port_ranges(spec: str) -> List[int]:
    ports: Set[int] = set()
    for part in (spec or "").split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            try:
                lo, hi = int(a), int(b)
                for p in range(max(1, lo), min(65535, hi) + 1):
                    ports.add(p)
            except Exception:
                continue
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(p)
            except Exception:
                continue
    return sorted(ports)


def _nmap_available() -> bool:
    return shutil.which("nmap") is not None


def _dns_query_bytes(qname: str = "example.com", qtype: int = 1) -> bytes:
    tid = random.getrandbits(16)
    flags = 0x0100  # recursion desired
    header = struct.pack("!HHHHHH", tid, flags, 1, 0, 0, 0)
    q = b""
    for label in qname.strip(".").split("."):
        b = label.encode("ascii", "ignore")
        q += bytes([len(b)]) + b
    q += b"\x00" + struct.pack("!HH", qtype, 1)  # QTYPE, QCLASS=IN
    return header + q


def _runs_dir() -> str:
    return os.path.join(os.getcwd(), "runs")


# ------------------------------------------------------------------------------
# Models
# ------------------------------------------------------------------------------
class StartRequest(BaseModel):
    target_ip: str = Field(..., description="IP of DUT (e.g., 192.168.8.1)")
    target_port: int = Field(..., ge=1, le=65535)
    transport: Literal["tcp", "udp"] = "tcp"
    interface: str = Field(..., description="Local NIC (e.g., wlan0)")
    duration_seconds: int = Field(60, description="0/negative = run until stop")
    engine: Literal["radamsa", "boofuzz", "custom", "proxy"] = "radamsa"
    seed_files: List[str] = Field(default_factory=list)
    extra_opts: Dict[str, Any] = Field(default_factory=dict)
    target: Optional[str] = None  # legacy "host:port"

    def get_host_port(self):
        if self.target_ip and self.target_port:
            return self.target_ip, int(self.target_port)
        if self.target and ":" in self.target:
            h, p = self.target.rsplit(":", 1)
            return h, int(p)
        raise ValueError("Target host/port not provided")


class StartMultiRequest(BaseModel):
    target_ip: str
    ports: List[int]
    transport: Literal["tcp", "udp"] = "tcp"
    interface: str
    duration_seconds: int = 60
    engine: Literal["radamsa", "boofuzz", "custom", "proxy"] = "radamsa"
    seed_files: List[str] = Field(default_factory=list)
    extra_opts: Dict[str, Any] = Field(default_factory=dict)
    instances: int = Field(1, ge=1, le=32)


class SeedGenRequest(BaseModel):
    kind: Literal["http", "dns", "ssh", "custom"] = "http"
    name: Optional[str] = None
    description: Optional[str] = None
    host: Optional[str] = None
    qname: Optional[str] = None
    payload_hex: Optional[str] = None


# ------------------------------------------------------------------------------
# Health/version/interfaces
# ------------------------------------------------------------------------------
@app.get("/api/healthz", include_in_schema=False)
async def healthz():
    return {"ok": True, "name": "VulnSpiral", "version": "0.1.5"}


@app.get("/api/version")
async def version(user=Depends(auth_dep)):
    return {"tool": "VulnSpiral", "version": "0.1.5"}


@app.get("/api/interfaces")
async def interfaces(user=Depends(auth_dep)):
    return {"interfaces": list_interfaces()}


# ------------------------------------------------------------------------------
# Seeds: list / upload / delete / generate
# ------------------------------------------------------------------------------
@app.get("/api/seeds")
async def seeds(user=Depends(auth_dep)):
    import json
    base = _seed_dir()
    items = []
    manifest = {}
    mpath = _seed_manifest_path()
    if os.path.isfile(mpath):
        try:
            with open(mpath, "r") as fh:
                manifest = json.load(fh)
        except Exception:
            manifest = {}
    if os.path.isdir(base):
        for fn in sorted(os.listdir(base)):
            fp = os.path.join(base, fn)
            if not os.path.isfile(fp) or fn.startswith(".") or fn == "seeds.json":
                continue
            item = {
                "name": manifest.get(fn, {}).get("name") or fn,
                "description": manifest.get(fn, {}).get("description") or "Seed file",
                "path": os.path.relpath(fp),
                "size": os.path.getsize(fp),
                "modified": int(os.path.getmtime(fp)),
            }
            items.append(item)
    return {"seeds": items}


@app.post("/api/seeds")
async def seed_upload(
    user=Depends(auth_dep),
    file: UploadFile = File(...),
    name: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
):
    import json, aiofiles
    base = _seed_dir()
    os.makedirs(base, exist_ok=True)
    mpath = _seed_manifest_path()
    manifest = {}
    if os.path.isfile(mpath):
        try:
            with open(mpath, "r") as fh:
                manifest = json.load(fh)
        except Exception:
            manifest = {}
    fname = _safe_basename(name or file.filename)
    fpath = os.path.join(base, fname)
    async with aiofiles.open(fpath, "wb") as out:
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break
            await out.write(chunk)
    manifest[fname] = {"name": name or fname, "description": description or manifest.get(fname, {}).get("description") or "Seed file"}
    with open(mpath, "w") as fh:
        json.dump(manifest, fh, indent=2)
    return {"ok": True, "seed": {"name": manifest[fname]["name"], "description": manifest[fname]["description"], "path": os.path.relpath(fpath)}}


@app.delete("/api/seeds/{filename}")
async def seed_delete(filename: str, user=Depends(auth_dep)):
    import json
    base = _seed_dir()
    mpath = _seed_manifest_path()
    fname = _safe_basename(filename)
    fpath = os.path.join(base, fname)
    if not fpath.startswith(base) or not os.path.isfile(fpath):
        raise HTTPException(status_code=404, detail="seed not found")
    os.remove(fpath)
    manifest = {}
    if os.path.isfile(mpath):
        try:
            with open(mpath, "r") as fh:
                manifest = json.load(fh)
        except Exception:
            manifest = {}
    if fname in manifest:
        del manifest[fname]
        with open(mpath, "w") as fh:
            json.dump(manifest, fh, indent=2)
    return {"ok": True, "deleted": fname}


@app.post("/api/seeds/generate")
async def seed_generate(req: SeedGenRequest, user=Depends(auth_dep)):
    import json
    base = _seed_dir()
    os.makedirs(base, exist_ok=True)
    ts = int(time.time())
    if req.kind == "http":
        host = req.host or "dut"
        payload = (f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: VulnSpiral\r\nAccept: */*\r\n\r\n").encode("ascii")
        fname = _safe_basename(req.name or f"http_seed_{ts}.txt")
        desc = req.description or "HTTP request seed"
    elif req.kind == "dns":
        qn = req.qname or "example.com"
        payload = _dns_query_bytes(qn, 1)
        fname = _safe_basename(req.name or f"dns_seed_{ts}.bin")
        desc = req.description or f"DNS A query seed for {qn}"
    elif req.kind == "ssh":
        payload = b"SSH-2.0-VulnSpiral_0.1\r\n"
        fname = _safe_basename(req.name or f"ssh_seed_{ts}.txt")
        desc = req.description or "SSH banner seed"
    else:
        if req.payload_hex:
            try:
                payload = bytes.fromhex(req.payload_hex.replace(" ", ""))
            except Exception:
                raise HTTPException(status_code=400, detail="Invalid payload_hex")
        else:
            payload = b"VULNSPIRAL-SEED\x00" * 8
        fname = _safe_basename(req.name or f"custom_seed_{ts}.bin")
        desc = req.description or "Custom binary seed"
    path = os.path.join(base, fname)
    with open(path, "wb") as fh:
        fh.write(payload)
    # update manifest
    mpath = _seed_manifest_path()
    manifest = {}
    if os.path.isfile(mpath):
        try:
            with open(mpath, "r") as fh:
                manifest = json.load(fh)
        except Exception:
            manifest = {}
    manifest[os.path.basename(path)] = {"name": fname, "description": desc}
    with open(mpath, "w") as fh:
        json.dump(manifest, fh, indent=2)
    return {"ok": True, "seed": {"name": fname, "description": desc, "path": os.path.relpath(path)}}


# ------------------------------------------------------------------------------
# Port scanning (legacy quick GET) - kept for compatibility
# ------------------------------------------------------------------------------
@app.get("/api/ports/scan")
async def scan_ports(
    ip: str = Query(...),
    tcp: int = Query(1),
    udp: int = Query(0),
    ports: Optional[str] = Query(None),
    method: str = Query("auto"),
    top_ports: Optional[int] = Query(None),
    timeout_ms: int = Query(300),
    user=Depends(auth_dep),
):
    res = {"ip": ip, "tcp_open": [], "udp_maybe_open": [], "method": "builtin"}

    if method == "nmap" and _nmap_available():
        res["method"] = "nmap"

        def _run_nmap(args: List[str]) -> str:
            try:
                out = subprocess.check_output(args, stderr=subprocess.STDOUT, timeout=max(5, top_ports or 0) * 2 or 30)
                return out.decode("utf-8", "ignore")
            except Exception:
                return ""

        if tcp:
            args = ["nmap", "-Pn", "-n", "-oX", "-", "-sT", ip]
            if top_ports:
                args += ["--top-ports", str(top_ports)]
            elif ports:
                args += ["-p", ports]
            xml = _run_nmap(args)
            if xml:
                try:
                    root = ET.fromstring(xml)
                    for host in root.findall(".//host/ports/port"):
                        if host.attrib.get("protocol") == "tcp":
                            p = int(host.attrib.get("portid", "0"))
                            state = host.find("state")
                            if state is not None and state.attrib.get("state") == "open":
                                res["tcp_open"].append(p)
                except Exception:
                    pass

        if udp:
            args = ["nmap", "-Pn", "-n", "-oX", "-", "-sU", ip]
            if top_ports:
                args += ["--top-ports", str(top_ports)]
            elif ports:
                args += ["-p", ports]
            xml = _run_nmap(args)
            if xml:
                try:
                    root = ET.fromstring(xml)
                    for host in root.findall(".//host/ports/port"):
                        if host.attrib.get("protocol") == "udp":
                            p = int(host.attrib.get("portid", "0"))
                            state = host.find("state")
                            if state is not None and state.attrib.get("state") in ("open", "open|filtered"):
                                res["udp_maybe_open"].append(p)
                except Exception:
                    pass

        res["tcp_open"] = sorted(set(res["tcp_open"]))
        res["udp_maybe_open"] = sorted(set(res["udp_maybe_open"]))
        return res

    # Built-in fallback
    plist = _parse_port_ranges(ports or "1-1024,22,53,80,443")
    res["method"] = "builtin"

    async def check_tcp(p):
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(max(0.05, timeout_ms / 1000.0))
            try:
                return p if s.connect_ex((ip, p)) == 0 else None
            except Exception:
                return None

    async def check_udp(p):
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(max(0.05, timeout_ms / 1000.0))
            try:
                s.sendto(b"", (ip, p))
                return p
            except Exception:
                return None

    tasks = []
    if tcp:
        tasks.extend(asyncio.create_task(check_tcp(p)) for p in plist)
    if udp:
        tasks.extend(asyncio.create_task(check_udp(p)) for p in plist)
    results = await asyncio.gather(*tasks) if tasks else []

    idx = 0
    if tcp:
        for p in plist:
            v = results[idx]; idx += 1
            if v:
                res["tcp_open"].append(v)
    if udp:
        ures = await asyncio.gather(*[check_udp(p) for p in plist])
        for p, v in zip(plist, ures):
            if v:
                res["udp_maybe_open"].append(p)

    res["tcp_open"] = sorted(set(res["tcp_open"]))
    res["udp_maybe_open"] = sorted(set(res["udp_maybe_open"]))
    return res


# ------------------------------------------------------------------------------
# Port scanning jobs with logs (start/stop/result + WS)
# ------------------------------------------------------------------------------
SCAN_JOBS: Dict[str, Dict[str, Any]] = {}  # scan_id -> {queue_list, stop, task, result, method, proc}


def _scan_job_publish(scan_id: str, msg: Dict[str, Any]):
    job = SCAN_JOBS.get(scan_id)
    if not job:
        return
    for q in list(job["queues"]):
        try:
            q.put_nowait(msg)
        except Exception:
            pass


async def _run_builtin_scan(scan_id: str, ip: str, tcp: bool, udp: bool, ports: str, timeout_ms: int, stop_evt: asyncio.Event):
    result = {"ip": ip, "tcp_open": [], "udp_maybe_open": [], "method": "builtin"}
    plist = _parse_port_ranges(ports or "1-1024,22,53,80,443")

    async def check_tcp(p):
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(max(0.05, timeout_ms / 1000.0))
            try:
                return p if s.connect_ex((ip, p)) == 0 else None
            except Exception:
                return None

    async def check_udp(p):
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(max(0.05, timeout_ms / 1000.0))
            try:
                s.sendto(b"", (ip, p))
                return p
            except Exception:
                return None

    # sequential to show progress
    if tcp:
        for p in plist:
            if stop_evt.is_set():
                break
            _scan_job_publish(scan_id, {"type": "progress", "message": f"TCP {p} ..."})
            v = await check_tcp(p)
            if v:
                result["tcp_open"].append(v)
    if udp:
        for p in plist:
            if stop_evt.is_set():
                break
            _scan_job_publish(scan_id, {"type": "progress", "message": f"UDP {p} ..."})
            v = await check_udp(p)
            if v:
                result["udp_maybe_open"].append(v)

    result["tcp_open"] = sorted(set(result["tcp_open"]))
    result["udp_maybe_open"] = sorted(set(result["udp_maybe_open"]))
    SCAN_JOBS[scan_id]["result"] = result
    _scan_job_publish(scan_id, {"type": "finished", "result": result})


async def _run_nmap_scan(scan_id: str, ip: str, tcp: bool, udp: bool, ports: Optional[str], top_ports: Optional[int], stop_evt: asyncio.Event):
    result = {"ip": ip, "tcp_open": [], "udp_maybe_open": [], "method": "nmap"}
    def _run(args: List[str]) -> str:
        # run nmap and return XML; emit heartbeat
        _scan_job_publish(scan_id, {"type": "progress", "message": " ".join(args)})
        try:
            proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            SCAN_JOBS[scan_id]["proc"] = proc
            while True:
                if stop_evt.is_set():
                    try:
                        proc.terminate()
                    except Exception:
                        pass
                    _scan_job_publish(scan_id, {"type": "error", "message": "Scan stopped by user"})
                    return ""
                line = proc.stdout.readline()
                if not line:
                    break
                # optional: stream human output lines for feedback
                _scan_job_publish(scan_id, {"type": "progress", "message": line.decode("utf-8", "ignore").strip()})
            out, _ = proc.communicate(timeout=1)
            return out.decode("utf-8", "ignore")
        except Exception as e:
            _scan_job_publish(scan_id, {"type": "error", "message": f"nmap failed: {e}"})
            return ""

    if tcp:
        args = ["nmap", "-Pn", "-n", "-oX", "-", "-sT", ip]
        if top_ports:
            args += ["--top-ports", str(top_ports)]
        elif ports:
            args += ["-p", ports]
        xml = _run(args)
        if xml:
            try:
                root = ET.fromstring(xml)
                for host in root.findall(".//host/ports/port"):
                    if host.attrib.get("protocol") == "tcp":
                        p = int(host.attrib.get("portid", "0"))
                        state = host.find("state")
                        if state is not None and state.attrib.get("state") == "open":
                            result["tcp_open"].append(p)
            except Exception:
                pass

    if udp:
        args = ["nmap", "-Pn", "-n", "-oX", "-", "-sU", ip]
        if top_ports:
            args += ["--top-ports", str(top_ports)]
        elif ports:
            args += ["-p", ports]
        xml = _run(args)
        if xml:
            try:
                root = ET.fromstring(xml)
                for host in root.findall(".//host/ports/port"):
                    if host.attrib.get("protocol") == "udp":
                        p = int(host.attrib.get("portid", "0"))
                        state = host.find("state")
                        if state is not None and state.attrib.get("state") in ("open", "open|filtered"):
                            result["udp_maybe_open"].append(p)
            except Exception:
                pass

    result["tcp_open"] = sorted(set(result["tcp_open"]))
    result["udp_maybe_open"] = sorted(set(result["udp_maybe_open"]))
    SCAN_JOBS[scan_id]["result"] = result
    _scan_job_publish(scan_id, {"type": "finished", "result": result})


@app.post("/api/ports/scan/start")
async def scan_start(
    user=Depends(auth_dep),
    ip: str = Form(...),
    method: str = Form("nmap"),        # "nmap" or "auto"
    tcp: int = Form(1),
    udp: int = Form(0),
    ports: Optional[str] = Form(None),
    top_ports: Optional[int] = Form(None),
    timeout_ms: int = Form(300),
):
    scan_id = str(uuid.uuid4())
    q: asyncio.Queue = asyncio.Queue()
    job = {"queues": [q], "stop": asyncio.Event(), "task": None, "result": None, "proc": None, "method": method}
    SCAN_JOBS[scan_id] = job
    # Start task
    if method == "nmap" and _nmap_available():
        task = asyncio.create_task(_run_nmap_scan(scan_id, ip, bool(tcp), bool(udp), ports, top_ports, job["stop"]))
    else:
        task = asyncio.create_task(_run_builtin_scan(scan_id, ip, bool(tcp), bool(udp), ports or "1-1024,22,53,80,443", timeout_ms, job["stop"]))
    job["task"] = task
    return {"scan_id": scan_id}


@app.post("/api/ports/scan/stop")
async def scan_stop(payload: Dict[str, str], user=Depends(auth_dep)):
    scan_id = payload.get("scan_id")
    job = SCAN_JOBS.get(scan_id or "")
    if not job:
        raise HTTPException(status_code=404, detail="scan not found")
    job["stop"].set()
    proc = job.get("proc")
    if proc:
        try:
            proc.terminate()
        except Exception:
            pass
    return {"status": "stopping", "scan_id": scan_id}


@app.get("/api/ports/scan/result/{scan_id}")
async def scan_result(scan_id: str, user=Depends(auth_dep)):
    job = SCAN_JOBS.get(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail="scan not found")
    return {"result": job.get("result")}


@app.websocket("/ws/scan/{scan_id}")
async def ws_scan(ws: WebSocket, scan_id: str):
    if JWT_SECRET:
        token = ws.query_params.get("token", "")
        try:
            jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        except Exception:
            await ws.close(code=4401)
            return

    job = SCAN_JOBS.get(scan_id)
    if not job:
        await ws.close(code=4404)
        return

    q: asyncio.Queue = asyncio.Queue()
    job["queues"].append(q)
    await ws.accept()
    try:
        # initial banner
        await ws.send_json({"type": "info", "message": f"Scan {scan_id} started (method={job.get('method')})."})
        while True:
            msg = await q.get()
            await ws.send_json(msg)
    except WebSocketDisconnect:
        job["queues"].remove(q)
    except Exception:
        try:
            job["queues"].remove(q)
        except Exception:
            pass
        try:
            await ws.close()
        except Exception:
            pass


# ------------------------------------------------------------------------------
# Fuzz start/plan/stop/pcap & status
# ------------------------------------------------------------------------------
@app.post("/api/fuzz/start")
async def start_fuzz(req: StartRequest, user=Depends(auth_dep)):
    try:
        host, port = req.get_host_port()
    except Exception:
        raise HTTPException(status_code=400, detail="Provide target_ip and target_port, or legacy 'target':'host:port'")

    if req.transport not in ("tcp", "udp"):
        raise HTTPException(status_code=400, detail="transport must be 'tcp' or 'udp'")

    if _is_remote_target(host) and not (req.extra_opts or {}).get("confirm_remote"):
        raise HTTPException(status_code=400, detail="Remote target requires extra_opts.confirm_remote=true")

    duration = int(req.duration_seconds)
    run_id = await manager.start_run(
        target=f"{host}:{port}",
        interface=req.interface,
        duration=duration,
        engine=req.engine,
        seed_files=req.seed_files or [],
        transport=req.transport,
        extra_opts=req.extra_opts or {},
    )
    return {"run_id": run_id}


@app.post("/api/fuzz/start_multi")
async def start_multi(req: StartMultiRequest, user=Depends(auth_dep)):
    host = req.target_ip
    ports = [p for p in (req.ports or []) if 1 <= int(p) <= 65535]
    if not ports:
        raise HTTPException(status_code=400, detail="No valid ports provided")
    if _is_remote_target(host) and not (req.extra_opts or {}).get("confirm_remote"):
        raise HTTPException(status_code=400, detail="Remote target requires extra_opts.confirm_remote=true")

    run_ids = []
    for p in ports:
        for _ in range(int(req.instances or 1)):
            rid = await manager.start_run(
                target=f"{host}:{p}",
                interface=req.interface,
                duration=int(req.duration_seconds),
                engine=req.engine,
                seed_files=req.seed_files or [],
                transport=req.transport,
                extra_opts=req.extra_opts or {},
            )
            run_ids.append(rid)
    plan_id = "plan-" + (run_ids[0][:8] if run_ids else "none")
    return {"plan_id": plan_id, "run_ids": run_ids, "count": len(run_ids)}


@app.post("/api/fuzz/stop")
async def stop_fuzz(payload: Dict[str, str], user=Depends(auth_dep)):
    run_id = payload.get("run_id")
    if not run_id:
        raise HTTPException(status_code=400, detail="run_id required")
    await manager.stop_run(run_id)
    return {"status": "stopping", "run_id": run_id}


@app.post("/api/fuzz/stop_all")
async def stop_all(user=Depends(auth_dep)):
    info = await manager.stop_all()
    return {"status": "stopping_all", "stopped": info}


@app.get("/api/fuzz/status")
async def status(user=Depends(auth_dep)):
    return manager.status()


@app.get("/api/fuzz/pcap/{run_id}")
async def get_pcap(run_id: str, user=Depends(auth_dep)):
    pcap_path = manager.get_pcap_path(run_id)
    if not pcap_path or not os.path.exists(pcap_path):
        raise HTTPException(status_code=404, detail="pcap not found")
    return FileResponse(
        pcap_path,
        media_type="application/vnd.tcpdump.pcap",
        filename=f"{run_id}.pcap",
    )


# ------------------------------------------------------------------------------
# PCAP browser: list + delete run
# ------------------------------------------------------------------------------
@app.get("/api/pcaps")
async def list_pcaps(user=Depends(auth_dep)):
    out = []
    base = _runs_dir()
    if not os.path.isdir(base):
        return {"pcaps": out}
    for run_id in sorted(os.listdir(base)):
        rdir = os.path.join(base, run_id)
        if not os.path.isdir(rdir):
            continue
        pcap = os.path.join(rdir, "pcaps", f"{run_id}.pcap")
        if os.path.isfile(pcap):
            size = os.path.getsize(pcap)
            mtime = int(os.path.getmtime(pcap))
            meta = {"target": None, "engine": None, "transport": None}
            cfg = os.path.join(rdir, "config.json")
            try:
                import json
                if os.path.isfile(cfg):
                    c = json.load(open(cfg))
                    meta["target"] = c.get("target")
                    meta["engine"] = c.get("engine")
                    meta["transport"] = c.get("transport")
            except Exception:
                pass
            out.append({"run_id": run_id, "pcap": os.path.relpath(pcap), "size": size, "modified": mtime, **meta})
    # newest first
    out.sort(key=lambda x: x["modified"], reverse=True)
    return {"pcaps": out}


_UUID_RE = re.compile(r"^[0-9a-fA-F-]{36}$")


@app.delete("/api/runs/{run_id}")
async def delete_run(run_id: str, user=Depends(auth_dep)):
    if not _UUID_RE.match(run_id):
        raise HTTPException(status_code=400, detail="invalid run_id")
    rdir = os.path.join(_runs_dir(), run_id)
    if not os.path.isdir(rdir):
        raise HTTPException(status_code=404, detail="run not found")
    try:
        shutil.rmtree(rdir)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"failed to delete: {e}")
    return {"ok": True, "deleted": run_id}


# ------------------------------------------------------------------------------
# WebSockets
# ------------------------------------------------------------------------------
@app.websocket("/ws/logs/{run_id}")
async def websocket_logs(ws: WebSocket, run_id: str):
    if JWT_SECRET:
        token = ws.query_params.get("token", "")
        try:
            jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        except Exception:
            await ws.close(code=4401)
            return

    await ws.accept()
    queue = manager.register_ws_client(run_id)
    try:
        while True:
            msg = await queue.get()
            await ws.send_json(msg)
    except WebSocketDisconnect:
        manager.unregister_ws_client(run_id, queue)
    except Exception:
        manager.unregister_ws_client(run_id, queue)
        try:
            await ws.close()
        except Exception:
            pass


@app.websocket("/ws/scan/{scan_id}")
async def websocket_scan(ws: WebSocket, scan_id: str):
    if JWT_SECRET:
        token = ws.query_params.get("token", "")
        try:
            jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        except Exception:
            await ws.close(code=4401)
            return

    job = SCAN_JOBS.get(scan_id)
    if not job:
        await ws.close(code=4404)
        return

    q: asyncio.Queue = asyncio.Queue()
    job["queues"].append(q)
    await ws.accept()
    try:
        await ws.send_json({"type": "info", "message": f"Scan {scan_id} connected."})
        while True:
            msg = await q.get()
            await ws.send_json(msg)
    except WebSocketDisconnect:
        try:
            job["queues"].remove(q)
        except Exception:
            pass
    except Exception:
        try:
            job["queues"].remove(q)
        except Exception:
            pass
        try:
            await ws.close()
        except Exception:
            pass
