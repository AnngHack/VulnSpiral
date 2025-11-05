#!/usr/bin/env bash
set -euo pipefail

# VulnSpiral bootstrap (no apt-get)
# - Builds CPython 3.11.10 from source (prefix .local_python/)
# - Creates venv .venv
# - Installs Python deps (merging user-provided requirement(s) if present)
# - Builds radamsa from source into vendor/bin/radamsa
# - Optionally builds the frontend if Node/npm is available

PY_VERSION="3.11.10"
PY_TARBALL="Python-${PY_VERSION}.tgz"
PY_URL="https://www.python.org/ftp/python/${PY_VERSION}/${PY_TARBALL}"
PY_SHA256="07a4356e912900e61a15cb0949a06c4a05012e213ecd6b4e84d0f67aabbee372"

ROOT_DIR="$(pwd)"
LOCAL_PY_DIR=".local_python/python-${PY_VERSION}"
VENV_DIR=".venv"
VENDOR_DIR="vendor"

echo "[+] VulnSpiral bootstrap starting"
mkdir -p "${VENDOR_DIR}" install_from_source

# ---------------------------------------------------------------------------
# 0) Quick sanity (tooling)
# ---------------------------------------------------------------------------
MISSING=()
for t in gcc make wget tar; do
  command -v "$t" >/dev/null 2>&1 || MISSING+=("$t")
done
if [ ${#MISSING[@]} -gt 0 ]; then
  echo "[-] Missing build tools: ${MISSING[*]}"
  cat <<'MSG'
Install these *manually* (no apt-get here):
  - gcc, g++, make
  - wget, tar
  - OpenSSL (headers), zlib, bzip2, xz, libffi, readline/ncurses, sqlite

Source downloads:
  * GCC:     https://gcc.gnu.org/install/
  * OpenSSL: https://www.openssl.org/source/
  * zlib:    https://zlib.net/
  * xz:      https://tukaani.org/xz/
  * libffi:  https://sourceware.org/libffi/
Re-run this script after prerequisites are present.
MSG
  exit 2
fi

# ---------------------------------------------------------------------------
# 1) Download & verify CPython
# ---------------------------------------------------------------------------
if [ ! -f "${PY_TARBALL}" ]; then
  echo "[+] Downloading CPython ${PY_VERSION}..."
  wget -O "${PY_TARBALL}" "${PY_URL}"
fi

if [ "${VS_SKIP_SHA256:-}" != "1" ]; then
  echo "[+] Verifying sha256..."
  SUM="$(sha256sum "${PY_TARBALL}" | awk '{print $1}')"
  if [ "$SUM" != "$PY_SHA256" ]; then
    echo "[-] SHA256 mismatch for ${PY_TARBALL}"
    echo "    Expected: ${PY_SHA256}"
    echo "    Got:      ${SUM}"
    echo "    Set VS_SKIP_SHA256=1 to bypass (NOT recommended)."
    exit 1
  fi
  echo "[+] SHA256 OK."
else
  echo "[!] VS_SKIP_SHA256=1 set — skipping checksum verification."
fi

# ---------------------------------------------------------------------------
# 2) Build CPython (prefix .local_python/python-3.11.10)
# ---------------------------------------------------------------------------
if [ ! -x "${LOCAL_PY_DIR}/bin/python3.11" ]; then
  echo "[+] Building CPython ${PY_VERSION}..."
  rm -rf build-python
  mkdir build-python
  tar -xzf "${PY_TARBALL}" -C build-python --strip-components=1
  pushd build-python >/dev/null
  ./configure --prefix="${ROOT_DIR}/${LOCAL_PY_DIR}" --enable-optimizations --with-ensurepip=install
  make -j"$(nproc || echo 2)"
  make install
  popd >/dev/null
else
  echo "[=] CPython ${PY_VERSION} already present at ${LOCAL_PY_DIR}"
fi

# ---------------------------------------------------------------------------
# 3) Create venv & upgrade pip
# ---------------------------------------------------------------------------
echo "[+] Creating virtualenv at ${VENV_DIR} ..."
"${LOCAL_PY_DIR}/bin/python3.11" -m venv "${VENV_DIR}"
"${VENV_DIR}/bin/pip" install --upgrade pip setuptools wheel

# ---------------------------------------------------------------------------
# 4) Merge requirements and install
# ---------------------------------------------------------------------------
echo "[+] Preparing requirements..."
BASE_REQ="requirements.txt"
TMP_REQ=".merged_requirements.txt"
cp "${BASE_REQ}" "${TMP_REQ}"

merge_req() {
  local f="$1"
  if [ -f "$f" ]; then
    echo "    - merging $f"
    cat "$f" >> "${TMP_REQ}"
  fi
}
# Common user filenames we auto-merge if they exist
merge_req "user_requirements.txt"
merge_req "requirements_user.txt"
merge_req "requirement.txt"
merge_req "requirment.txt"

# de-duplicate & sort
sort -u -o "${BASE_REQ}" "${TMP_REQ}"
rm -f "${TMP_REQ}"

echo "[+] Installing Python dependencies ..."
"${VENV_DIR}/bin/pip" install -r "${BASE_REQ}"

# ---------------------------------------------------------------------------
# 5) Build radamsa from source into vendor/bin/
# ---------------------------------------------------------------------------
echo "[+] Building radamsa from source into vendor/bin ..."
chmod +x install_from_source/build_radamsa.sh
./install_from_source/build_radamsa.sh "${VENDOR_DIR}"

# ---------------------------------------------------------------------------
# 6) Optional: build frontend if npm present
# ---------------------------------------------------------------------------
if command -v npm >/dev/null 2>&1; then
  echo "[+] npm detected — building frontend"
  pushd frontend >/dev/null
  npm install
  npm run build
  popd >/dev/null
else
  echo "[=] npm not found — skipping frontend build. (UI still works via /help and /api; build later with: cd frontend && npm i && npm run build)"
fi

echo
echo "[✓] Bootstrap complete."
echo "Activate venv:  source ${VENV_DIR}/bin/activate"
echo "Run backend:    python -m uvicorn vulnspiral.server:app --host 0.0.0.0 --port 8000 --reload"
echo
echo "If radamsa is also installed system-wide at /usr/bin/radamsa, the tool will prefer vendor/bin/radamsa but can fall back to /usr/bin/radamsa."
