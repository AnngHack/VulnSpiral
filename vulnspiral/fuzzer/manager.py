import os
import json
import time
import uuid
import asyncio
from typing import Dict, Any, Optional, List
from collections import defaultdict

from vulnspiral.logger import get_run_logger
from vulnspiral.utils.pcap_writer import PcapWriterHelper
from vulnspiral.fuzzer.engines.radamsa_engine import RadamsaEngine
from vulnspiral.fuzzer.engines.boofuzz_engine import BoofuzzEngine
from vulnspiral.fuzzer.engines.custom_engine import CustomEngine
from vulnspiral.fuzzer.engines.proxy_engine import ProxyEngine

RUNS_DIR = os.path.join(os.getcwd(), "runs")

class FuzzContext:
    def __init__(self, run_id: str, cfg: Dict[str, Any]):
        self.run_id = run_id
        self.cfg = cfg
        self.logger = get_run_logger(run_id)
        self.start_time = time.time()
        self.sent = 0
        self.errors = 0
        self.pcap_path: Optional[str] = None
        self._stop_event = asyncio.Event()
        self._engine_task: Optional[asyncio.Task] = None

class FuzzManager:
    def __init__(self):
        self.runs: Dict[str, FuzzContext] = {}
        self.engines = {
            "radamsa": RadamsaEngine,
            "boofuzz": BoofuzzEngine,
            "custom": CustomEngine,
            "proxy": ProxyEngine,
        }
        self.ws_clients: Dict[str, List[asyncio.Queue]] = defaultdict(list)

    async def start_run(self, target: str, interface: str, duration: int, engine: str,
                        seed_files: List[str], transport: str, extra_opts: Dict[str, Any]) -> str:
        os.makedirs(RUNS_DIR, exist_ok=True)
        run_id = str(uuid.uuid4())
        run_dir = os.path.join(RUNS_DIR, run_id)
        os.makedirs(run_dir, exist_ok=True)

        cfg = dict(
            target=target, interface=interface, duration=duration, engine=engine,
            seed_files=seed_files, transport=transport, extra_opts=extra_opts
        )
        ctx = FuzzContext(run_id, cfg)
        self.runs[run_id] = ctx

        # Persist config/tool metadata for evidence
        with open(os.path.join(run_dir, "config.json"), "w") as f:
            json.dump(cfg, f, indent=2)
        with open(os.path.join(run_dir, "tool.json"), "w") as f:
            json.dump({"tool_name": "VulnSpiral", "version": "0.1.3"}, f, indent=2)

        ctx.logger.info(
            f"Starting run {run_id} engine={engine} transport={transport} iface={interface} target={target} duration={duration}"
        )

        # PCAP helper
        pcap_helper = PcapWriterHelper(run_id, interface)
        ctx.pcap_path = pcap_helper.pcap_path
        pcap_helper.start_sniff_background(ctx._stop_event, logger=ctx.logger)

        # Choose engine
        EngineCls = self.engines.get(engine)
        if not EngineCls:
            raise RuntimeError(f"Unknown engine {engine}")
        engine_inst = EngineCls(ctx, pcap_helper)

        # Launch engine task
        ctx._engine_task = asyncio.create_task(self._run_engine(run_id, engine_inst, duration, pcap_helper))
        return run_id

    async def _run_engine(self, run_id, engine_inst, duration, pcap_helper: PcapWriterHelper):
        ctx = self.runs[run_id]
        try:
            await engine_inst.start()
            if duration and duration > 0:
                end = time.time() + duration
                while time.time() < end and not ctx._stop_event.is_set():
                    await asyncio.sleep(1.0)
                    await self._publish(run_id, {"type": "heartbeat", "sent": ctx.sent, "errors": ctx.errors})
            else:
                # run until stop
                while not ctx._stop_event.is_set():
                    await asyncio.sleep(1.0)
                    await self._publish(run_id, {"type": "heartbeat", "sent": ctx.sent, "errors": ctx.errors})
            await engine_inst.stop()
        except Exception as e:
            ctx.logger.exception("Engine failed")
            await self._publish(run_id, {"type": "error", "message": str(e)})
        finally:
            ctx._stop_event.set()
            pcap_helper.close()
            await self._publish(run_id, {"type": "finished", "pcap": ctx.pcap_path})

    async def stop_run(self, run_id: str):
        ctx = self.runs.get(run_id)
        if not ctx:
            return
        ctx._stop_event.set()
        if ctx._engine_task:
            try:
                await asyncio.wait_for(ctx._engine_task, timeout=10)
            except Exception:
                pass

    async def stop_all(self):
        run_ids = list(self.runs.keys())
        for rid in run_ids:
            await self.stop_run(rid)
        return run_ids

    def status(self):
        out = {}
        for run_id, ctx in self.runs.items():
            out[run_id] = {
                "cfg": ctx.cfg, "sent": ctx.sent, "errors": ctx.errors, "pcap": ctx.pcap_path
            }
        return out

    def get_pcap_path(self, run_id: str) -> Optional[str]:
        ctx = self.runs.get(run_id)
        return ctx.pcap_path if ctx else None

    def register_ws_client(self, run_id: str) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue()
        self.ws_clients[run_id].append(q)
        return q

    def unregister_ws_client(self, run_id: str, queue: asyncio.Queue):
        if queue in self.ws_clients.get(run_id, []):
            self.ws_clients[run_id].remove(queue)

    async def _publish(self, run_id: str, msg: Dict[str, Any]):
        for q in list(self.ws_clients.get(run_id, [])):
            try:
                await q.put(msg)
            except Exception:
                pass
