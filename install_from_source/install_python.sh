#!/usr/bin/env bash
set -euo pipefail
# Helper to build CPython 3.11.10 in a given prefix (used by setup_bootstrap.sh)

PREFIX="${1:-.local_python/python-3.11.10}"
PY_VERSION="3.11.10"
PY_TARBALL="Python-${PY_VERSION}.tgz"
PY_URL="https://www.python.org/ftp/python/${PY_VERSION}/${PY_TARBALL}"
PY_SHA256="07a4356e912900e61a15cb0949a06c4a05012e213ecd6b4e84d0f67aabbee372"

echo "[+] Installing CPython ${PY_VERSION} into ${PREFIX}"

if [ ! -f "${PY_TARBALL}" ]; then
  wget -O "${PY_TARBALL}" "${PY_URL}"
fi

if [ "${VS_SKIP_SHA256:-}" != "1" ]; then
  SUM="$(sha256sum "${PY_TARBALL}" | awk '{print $1}')"
  if [ "$SUM" != "$PY_SHA256" ]; then
    echo "[-] SHA256 mismatch for ${PY_TARBALL}"
    exit 1
  fi
fi

rm -rf build-python
mkdir build-python
tar -xzf "${PY_TARBALL}" -C build-python --strip-components=1
pushd build-python >/dev/null
./configure --prefix="$(pwd)/../${PREFIX}" --enable-optimizations --with-ensurepip=install
make -j"$(nproc || echo 2)"
make install
popd >/dev/null

echo "[✓] Python installed at ${PREFIX}"
