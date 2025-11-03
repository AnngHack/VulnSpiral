# VulnSpiral — Protocol & Application Fuzzer

VulnSpiral is a full-featured fuzzing framework with a FastAPI backend and a React single-page frontend for testing networked devices under test (DUTs), such as Wi-Fi CPEs. It supports seed-based mutational fuzzing (radamsa), session fuzzing (boofuzz), a simple custom/Scapy mutator, per-run PCAP capture, integrated port scanning (nmap or builtin), live logs (separate fuzz vs. scan), seed generation/management in the UI, a PCAP manager, and an evidence collector aligned to ITSAR requirements.

Important: Use only against systems you own or have explicit written permission to test.

---

## Table of Contents

1. Features  
2. Repository Layout  
3. Download / Clone  
4. Quick Bootstrap (Recommended)  
5. Manual Step-by-Step Setup (Complete)  
   5.1 Prerequisites (install manually, no apt-get)  
   5.2 Build CPython 3.11.10 from source  
   5.3 Create and activate virtual environment  
   5.4 Install Python dependencies (requirements merging)  
   5.5 Build radamsa from source  
   5.6 Build frontend (npm)  
6. Run the Backend and Open the UI  
7. Using the Web UI  
   7.1 Typical Workflow  
   7.2 Seeds in the UI  
   7.3 Engines  
   7.4 Artifacts Per Run  
8. Command Line Tools  
9. Tests  
10. Configuration and Environment Variables  
11. How This Satisfies ITSAR Fuzzing Evidence Requirements  
12. Troubleshooting  
13. Security Notes  
14. Roadmap  
15. License

---

## 1. Features

- Web UI (React SPA) and FastAPI backend  
- Engines: radamsa, boofuzz, custom (Scapy), proxy  
- Interface selection (wlan0, eth0, etc.)  
- TCP and UDP fuzzing  
- Per-run PCAP capture and run logs  
- Port scanner (nmap “no ping” mode or builtin), with Start/Stop and live scan log  
- Apply discovered ports into fuzz form (auto-selects TCP/UDP)  
- Seed management in the UI: generate, select, delete; hover for descriptions  
- PCAP manager in the UI: list all runs, download, delete  
- Evidence helper for ITSAR-style reporting  
- No apt-get usage in scripts; bootstrap prints links for manual system dependencies

---

## 2. Repository Layout

```text
VulnSpiral/
├─ LICENSE
├─ README.md
├─ setup_bootstrap.sh
├─ install_from_source/
│  ├─ install_python.sh
│  └─ build_radamsa.sh
├─ requirements.txt
├─ vulnspiral/
│  ├─ __main__.py
│  ├─ server.py
│  ├─ logger.py
│  ├─ fuzzer/
│  │  ├─ __init__.py
│  │  ├─ manager.py
│  │  └─ engines/
│  │     ├─ __init__.py
│  │     ├─ radamsa_engine.py
│  │     ├─ boofuzz_engine.py
│  │     └─ custom_engine.py
│  └─ utils/
│     ├─ __init__.py
│     ├─ pcap_writer.py
│     └─ netiface.py
├─ frontend/
│  ├─ package.json
│  ├─ README.frontend.md
│  ├─ public/
│  │  ├─ index.html
│  │  └─ help.html
│  └─ src/
│     ├─ App.jsx
│     ├─ index.jsx
│     ├─ components/
│     │  ├─ FuzzForm.jsx
│     │  ├─ ScanPanel.jsx
│     │  ├─ LogViewer.jsx
│     │  ├─ ScanLogViewer.jsx
│     │  ├─ PcapManager.jsx
│     │  └─ StatusBadge.jsx
│     └─ styles.css
├─ examples/
│  ├─ seed_samples/
│  │  ├─ tcp_seed.bin
│  │  └─ http_seed.txt
│  └─ local_echo_server.py
├─ tests/
│  └─ test_fuzz_start_stop.py
├─ tools/
│  └─ collect_evidence.py
└─ runs/   (generated at runtime)
```

---

## 3. Download / Clone

```bash
git clone https://github.com/yourname/VulnSpiral.git
cd VulnSpiral
```
Replace the repository URL with your own.

---

## 4. Quick Bootstrap (Recommended)

This will build CPython 3.11.10 locally, create a virtualenv, install Python dependencies, build radamsa from source, and build the UI if npm is available.

```bash
chmod +x setup_bootstrap.sh install_from_source/*.sh
./setup_bootstrap.sh

# Activate the environment
source .venv/bin/activate

# If you prefer to build the frontend manually (or bootstrap skipped npm):
cd frontend && npm install && npm run build && cd ..

# Run the backend
python -m uvicorn vulnspiral.server:app --host 0.0.0.0 --port 8000 --reload
```

Open in a browser:
- UI: http://<kali-ip>:8000/ui/
- Help: http://<kali-ip>:8000/help

---

## 5. Manual Step-by-Step Setup (Complete)

Use this if you do not want to run the bootstrap script.

### 5.1 Prerequisites (install manually, no apt-get)

Install or build from source:
- gcc, g++, make, wget, tar
- OpenSSL headers, zlib headers, bzip2 headers, xz/liblzma headers
- libffi headers, readline/ncurses headers, sqlite3 headers
- Optional: git (for cloning radamsa), node/npm (to build UI), nmap (for nmap scan mode)

Useful sources:
- GCC: https://gcc.gnu.org/install/
- OpenSSL: https://www.openssl.org/source/
- zlib: https://zlib.net/
- xz: https://tukaani.org/xz/
- libffi: https://sourceware.org/libffi/
- nmap: https://nmap.org/download.html

### 5.2 Build CPython 3.11.10 from source

Artifact:
- URL: https://www.python.org/ftp/python/3.11.10/Python-3.11.10.tgz
- SHA256: 07a4356e912900e61a15cb0949a06c4a05012e213ecd6b4e84d0f67aabbee372

Commands:
```bash
wget https://www.python.org/ftp/python/3.11.10/Python-3.11.10.tgz
echo "07a4356e912900e61a15cb0949a06c4a05012e213ecd6b4e84d0f67aabbee372  Python-3.11.10.tgz" | sha256sum -c -
mkdir -p build-python
tar -xzf Python-3.11.10.tgz -C build-python --strip-components=1
pushd build-python
./configure --prefix="$(pwd)/../.local_python/python-3.11.10" --enable-optimizations --with-ensurepip=install
make -j"$(nproc || echo 2)"
make install
popd
```
You should now have: `.local_python/python-3.11.10/bin/python3.11`

Alternatively:
```bash
chmod +x install_from_source/install_python.sh
./install_from_source/install_python.sh .local_python/python-3.11.10
```

### 5.3 Create and activate virtual environment

```bash
.local_python/python-3.11.10/bin/python3.11 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip setuptools wheel
```

### 5.4 Install Python dependencies (requirements merging)

```bash
pip install -r requirements.txt
```
If you provide a user requirements file, the bootstrap merges these automatically when present (deduplicated):
- user_requirements.txt
- requirements_user.txt
- requirement.txt
- requirment.txt

### 5.5 Build radamsa from source

```bash
chmod +x install_from_source/build_radamsa.sh
./install_from_source/build_radamsa.sh vendor
```
This places `vendor/bin/radamsa`. If you already have `/usr/bin/radamsa`, the backend prefers `vendor/bin/radamsa` but can fallback to `/usr/bin/radamsa`.

### 5.6 Build frontend (npm)

```bash
cd frontend
npm install
npm run build
cd ..
```
This produces `frontend/dist/` which is served at `/ui` by the backend.

---

## 6. Run the Backend and Open the UI

```bash
source .venv/bin/activate
python -m uvicorn vulnspiral.server:app --host 0.0.0.0 --port 8000 --reload
```
Browse:
- UI: http://<kali-ip>:8000/ui/
- Help: http://<kali-ip>:8000/help

---

## 7. Using the Web UI

The UI has two main columns. Left: Fuzz Target. Right: Scan and Seeds. Below: separate logs for fuzzing and port scanning. A PCAP manager at the bottom lists all run captures and allows download/delete.

### 7.1 Typical Workflow

1. Scan the DUT:
   - Enter target IP on the right panel.
   - Choose scanner: nmap (no ping) or builtin.
   - Choose ports preset: Top 1000, Recommended, All, or Custom ranges.
   - Start scan and watch the Port Scan Log.
   - When ports appear, click Use TCP <port> or Use UDP <port>. This fills in the fuzz form and auto-selects transport.

2. Start a fuzz run:
   - On the left panel, verify target IP, port, transport (TCP/UDP), and interface (e.g., wlan0).
   - Choose engine: radamsa, boofuzz, custom, or proxy.
   - Pick duration and throttle.
   - Select one or more seeds.
   - Click Start fuzz and observe the Fuzz Log. One PCAP file is created per run.
   - Use Stop current or Stop all as needed.

3. Manage PCAPs:
   - Use the PCAPs table to download or delete any run capture.

### 7.2 Seeds in the UI

- Generate seeds: HTTP, DNS, SSH, or Custom (hex payload or an auto-generated pattern).
- Seeds are stored at `examples/seed_samples/`.
- Hover a seed entry to see its description.
- Delete unneeded seeds from the list.

### 7.3 Engines

- radamsa: mutation engine that fuzzes input bytes from provided seeds. Good for quickly surfacing parser crashes.
- boofuzz: session/field-aware fuzzing. Supply templates when you want grammar-aware testing.
- custom: Scapy-based mutator for packet crafting.
- proxy: local proxy that relays and mutates transit traffic. Configure a local bind port and point your client to it.

### 7.4 Artifacts Per Run

```text
runs/<run_id>/
  config.json            # run parameters and metadata
  logs/run.log           # run-time events and counters
  pcaps/<run_id>.pcap    # network capture of the run
```

---

## 8. Command Line Tools

Evidence collection:

```bash
source .venv/bin/activate
python tools/collect_evidence.py <run_id>
```
This produces a JSON/HTML summary referencing config, logs, and PCAP for the given run. Use this for ITSAR-friendly reporting.

---

## 9. Tests

Integration test:

```bash
# Terminal 1
python examples/local_echo_server.py 127.0.0.1 9000

# Terminal 2
source .venv/bin/activate
pytest -q
```
This verifies that a short fuzz run produces a PCAP and logs.

---

## 10. Configuration and Environment Variables

- VULNSPIRAL_JWT_SECRET: if set, API and WebSockets require Bearer JWTs.
- VS_SKIP_SHA256=1: skip Python tarball checksum verification during bootstrap (not recommended).
- RADAMSA_PATH: optional override path to radamsa binary.

Start server:
```bash
source .venv/bin/activate
python -m uvicorn vulnspiral.server:app --host 0.0.0.0 --port 8000 --reload
```

---

## 11. How This Satisfies ITSAR Fuzzing Evidence Requirements

This tool’s outputs map to common fuzzing evidence requirements and reference your uploaded ITSAR requirement file via the citation tokens below.

- Tool identity and version: available from /api/version and included in evidence.
- Test settings: runs/<run_id>/config.json records target, interface, engine, seeds, transport, duration, throttle, and anomaly profile.
- Execution output: runs/<run_id>/logs/run.log contains event logs and counters.
- Artifacts: runs/<run_id>/pcaps/<run_id>.pcap contains the packet trace.
- Evidence packaging: tools/collect_evidence.py aggregates the above into a concise bundle.

Citations you requested for the uploaded requirements:
- :contentReference[oaicite:1]{index=1}
- :contentReference[oaicite:2]{index=2}

---

## 12. Troubleshooting

- 304 Not Modified in server logs: normal browser conditional requests for static assets.
- uvicorn not found when running .venv/bin/uvicorn: use python -m uvicorn to ensure the venv interpreter is used.
- Pydantic error mentioning “regex removed” or v1 API: upgrade pydantic to v2 (requirements already specify v2).
- Empty or missing PCAP: verify correct interface selection and required privileges; raw capture may require elevated permissions on some OSes.
- Help page 404: backend serves /help and /help.html regardless of UI build; /ui/help redirects to /help.
- Bootstrap missing toolchains: install gcc, make, headers, etc. manually and re-run ./setup_bootstrap.sh.

---

## 13. Security Notes

- Only test systems you own or have explicit permission to test.
- Use isolated networks or VLANs to contain test traffic.
- Expect DUT hangs or reboots; monitor via console or UART and external logging.
- Consider setting VULNSPIRAL_JWT_SECRET for shared lab environments.

---

## 14. Roadmap

- Batch plan runner to fuzz all discovered open ports automatically
- CVSS and CWE anomaly profiling and reporting enhancements
- Distributed runners for scaling out
- Grammar-based generational protocol suites

---

## 15. License

MIT License. See LICENSE for details.
