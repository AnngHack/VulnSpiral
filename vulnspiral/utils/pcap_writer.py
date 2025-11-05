import os
import threading
from typing import Optional
from scapy.utils import PcapWriter
from scapy.all import Ether, IP, TCP, UDP, Raw, sniff

class PcapWriterHelper:
    """
    Writes packets to runs/<run_id>/pcaps/<run_id>.pcap.
    Also supports a background sniffer (best-effort if permissions allow).
    """
    def __init__(self, run_id: str, interface: str):
        self.run_id = run_id
        self.interface = interface
        self.run_dir = os.path.join(os.getcwd(), "runs", self.run_id)
        os.makedirs(os.path.join(self.run_dir, "pcaps"), exist_ok=True)
        self.pcap_path = os.path.join(self.run_dir, "pcaps", f"{run_id}.pcap")
        self._writer = PcapWriter(self.pcap_path, append=True, sync=True)
        self._sniff_thread: Optional[threading.Thread] = None
        self._stop_evt: Optional[threading.Event] = None

    def write_packet(self, pkt):
        try:
            self._writer.write(pkt)
        except Exception:
            self._writer.write(Raw(load=bytes(pkt)))

    def write_raw(self, payload: bytes, dst_host: str, dst_port: int, transport: str = "tcp"):
        try:
            if transport == "udp":
                pkt = Ether()/IP(dst=dst_host)/UDP(dport=dst_port)/Raw(load=payload)
            else:
                pkt = Ether()/IP(dst=dst_host)/TCP(dport=dst_port)/Raw(load=payload)
            self._writer.write(pkt)
        except Exception:
            self._writer.write(Raw(load=payload))

    def start_sniff_background(self, stop_event, logger=None):
        # Start a background thread that sniffs with small timeouts; robust to stop signals
        self._stop_evt = stop_event

        def _loop():
            if logger:
                logger.info(f"[pcap] starting sniff on iface={self.interface} (best-effort)")
            while not self._stop_evt.is_set():
                try:
                    sniff(iface=self.interface, prn=self._writer.write, store=False, timeout=1)
                except Exception as e:
                    if logger:
                        logger.warning(f"[pcap] sniff error: {e} (continuing best-effort)")
                    break

        self._sniff_thread = threading.Thread(target=_loop, daemon=True)
        self._sniff_thread.start()

    def close(self):
        try:
            if self._sniff_thread and self._sniff_thread.is_alive():
                pass
        finally:
            try:
                self._writer.close()
            except Exception:
                pass
