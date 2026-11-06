#!/usr/bin/env bash
# Unduh sidecar (versi di-pin) + verifikasi SHA-256 checksum rilis resmi -> src-tauri/binaries/<nama>-<target-triple>[.exe]
# Lintas-OS: Linux, macOS, Windows (dipilih dari target-triple rustc). Perlu: rustc, curl, python3.
# SIDECAR_DIR=/usr/local/bin -> pasang tanpa suffix triple (dipakai image CI Linux).
# Semgrep tidak di-bundle (aplikasi Python): pasang terpisah, mis. `uv tool install semgrep`.
set -euo pipefail
GITLEAKS=8.30.1
TRIVY=0.76.1
NUCLEI=3.11.1

TRIPLE="$(rustc -vV | sed -n 's/host: //p')"
case "$TRIPLE" in
  *windows*) OS=windows; EXT=.exe ;;
  *darwin*|*apple*) OS=darwin; EXT= ;;
  *) OS=linux; EXT= ;;
esac
case "$TRIPLE" in aarch64*|arm64*) ARM=1 ;; *) ARM=0 ;; esac

if [ -n "${SIDECAR_DIR:-}" ]; then
  OUT=$SIDECAR_DIR; SUFFIX=
else
  OUT="$(cd "$(dirname "$0")/.." && pwd)/src-tauri/binaries"; SUFFIX="-$TRIPLE"
fi
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
mkdir -p "$OUT"; cd "$TMP"

sha256() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }

# asset_for <gitleaks|trivy|nuclei>
asset_for() {
  case "$1" in
    gitleaks) case "$OS" in
        windows) echo "gitleaks_${GITLEAKS}_windows_x64.zip" ;;
        darwin)  [ $ARM = 1 ] && echo "gitleaks_${GITLEAKS}_darwin_arm64.tar.gz" || echo "gitleaks_${GITLEAKS}_darwin_x64.tar.gz" ;;
        *)       [ $ARM = 1 ] && echo "gitleaks_${GITLEAKS}_linux_arm64.tar.gz" || echo "gitleaks_${GITLEAKS}_linux_x64.tar.gz" ;;
      esac ;;
    trivy) case "$OS" in
        windows) echo "trivy_${TRIVY}_windows-64bit.zip" ;;
        darwin)  [ $ARM = 1 ] && echo "trivy_${TRIVY}_macOS-ARM64.tar.gz" || echo "trivy_${TRIVY}_macOS-64bit.tar.gz" ;;
        *)       [ $ARM = 1 ] && echo "trivy_${TRIVY}_Linux-ARM64.tar.gz" || echo "trivy_${TRIVY}_Linux-64bit.tar.gz" ;;
      esac ;;
    nuclei) case "$OS" in
        windows) echo "nuclei_${NUCLEI}_windows_amd64.zip" ;;
        darwin)  [ $ARM = 1 ] && echo "nuclei_${NUCLEI}_macOS_arm64.zip" || echo "nuclei_${NUCLEI}_macOS_amd64.zip" ;;
        *)       [ $ARM = 1 ] && echo "nuclei_${NUCLEI}_linux_arm64.zip" || echo "nuclei_${NUCLEI}_linux_amd64.zip" ;;
      esac ;;
  esac
}

# fetch <repo> <version> <tool>
fetch() {
  local repo=$1 ver=$2 tool=$3
  local asset checks url bin=$tool$EXT
  asset=$(asset_for "$tool")
  checks="${tool}_${ver}_checksums.txt"
  url="https://github.com/$repo/releases/download/v$ver"
  curl -fsSLO "$url/$asset" -O "$url/$checks"
  local want got
  want=$(grep -E "[[:space:]][*]?${asset}\$" "$checks" | head -1 | awk '{print $1}')
  got=$(sha256 "$asset")
  [ -n "$want" ] && [ "$want" = "$got" ] || { echo "Checksum $asset gagal (want=$want got=$got)"; exit 1; }
  rm -rf x && mkdir x
  local py; py=$(command -v python3 || command -v python)
  "$py" - "$asset" x <<'PY'
import sys, os, zipfile, tarfile
arc, dest = sys.argv[1], sys.argv[2]
(zipfile.ZipFile(arc) if arc.endswith('.zip') else tarfile.open(arc)).extractall(dest)
PY
  local found
  found=$(find x -type f -name "$bin" | head -1)
  [ -n "$found" ] || { echo "Binary $bin tidak ada di $asset"; exit 1; }
  install -m755 "$found" "$OUT/$tool$SUFFIX$EXT"
  rm -rf x
}

fetch gitleaks/gitleaks "$GITLEAKS" gitleaks
fetch aquasecurity/trivy "$TRIVY" trivy
fetch projectdiscovery/nuclei "$NUCLEI" nuclei
ls -l "$OUT"
