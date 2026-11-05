#!/usr/bin/env bash
# Unduh sidecar (versi di-pin) + verifikasi checksum rilis resmi -> src-tauri/binaries/<nama>-<target-triple>
# SIDECAR_DIR=/usr/local/bin -> pasang tanpa suffix triple (dipakai image CI).
# Semgrep tidak di-bundle (aplikasi Python): pasang terpisah, mis. `uv tool install semgrep`.
set -euo pipefail
GITLEAKS=8.30.1
TRIVY=0.76.1
NUCLEI=3.11.1
if [ -n "${SIDECAR_DIR:-}" ]; then
  OUT=$SIDECAR_DIR; SUFFIX=
else
  OUT="$(cd "$(dirname "$0")/.." && pwd)/src-tauri/binaries"; SUFFIX="-$(rustc -vV | sed -n 's/host: //p')"
fi
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
mkdir -p "$OUT"; cd "$TMP"

fetch() { # url-dir tarball checksums binary
  curl -fsSLO "$1/$2" -O "$1/$3"
  sha256sum --ignore-missing -c "$3"
  mkdir x
  case "$2" in
    *.zip) python3 -c 'import sys,zipfile; zipfile.ZipFile(sys.argv[1]).extract(sys.argv[2], "x")' "$2" "$4" ;;
    *) tar -xzf "$2" -C x "$4" ;;
  esac
  install -m755 "x/$4" "$OUT/$4$SUFFIX" && rm -rf x
}
fetch https://github.com/gitleaks/gitleaks/releases/download/v$GITLEAKS gitleaks_${GITLEAKS}_linux_x64.tar.gz gitleaks_${GITLEAKS}_checksums.txt gitleaks
fetch https://github.com/aquasecurity/trivy/releases/download/v$TRIVY trivy_${TRIVY}_Linux-64bit.tar.gz trivy_${TRIVY}_checksums.txt trivy
fetch https://github.com/projectdiscovery/nuclei/releases/download/v$NUCLEI nuclei_${NUCLEI}_linux_amd64.zip nuclei_${NUCLEI}_checksums.txt nuclei
ls -l "$OUT"
