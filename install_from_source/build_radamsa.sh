#!/usr/bin/env bash
set -euo pipefail
# Build radamsa from source and place binary under <vendor>/bin/radamsa

DEST_ROOT="${1:-vendor}"
DEST_BIN="${DEST_ROOT}/bin"
REPO_URL="https://github.com/aoh/radamsa.git"

mkdir -p "${DEST_BIN}"

if [ ! -d "radamsa-src" ]; then
  echo "[+] Cloning radamsa..."
  git clone --depth=1 "${REPO_URL}" radamsa-src
else
  echo "[=] radamsa-src exists, updating..."
  pushd radamsa-src >/dev/null
  git pull --ff-only || true
  popd >/dev/null
fi

echo "[+] Building radamsa..."
pushd radamsa-src >/dev/null
# radamsa uses a Makefile; requires make & a C compiler
make
popd >/dev/null

echo "[+] Installing radamsa -> ${DEST_BIN}/radamsa"
cp -f radamsa-src/bin/radamsa "${DEST_BIN}/radamsa"
chmod +x "${DEST_BIN}/radamsa"

echo "[✓] radamsa available at ${DEST_BIN}/radamsa"
