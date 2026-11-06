#!/usr/bin/env bash
# Pasang entri .desktop + ikon agar dock/launcher Ubuntu menampilkan ikon Antareja saat `cargo tauri dev`.
# Perlu karena di Linux ikon dock dicocokkan ke file .desktop lewat app-id window, bukan dari window-nya.
# Di Wayland app-id = nama program = basename binary (dev: "appsec-scanner"); maka nama file .desktop harus sama.
# Untuk rilis, pasang paket .deb (npm run build:linux) — bundler Tauri sudah membuat entri yang cocok otomatis.
set -euo pipefail

NAME="Antareja"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
ICON_SRC="$REPO/ui/src/assets/antareja.svg"

BIN="$REPO/target/release/appsec-scanner"
[ -x "$BIN" ] || BIN="$REPO/target/debug/appsec-scanner"
APP_ID="$(basename "$BIN")"   # = app-id Wayland yang dicocokkan GNOME

ICON_DIR="$HOME/.local/share/icons/hicolor/256x256/apps"
APP_DIR="$HOME/.local/share/applications"
ICON_PNG="$ICON_DIR/$APP_ID.png"
mkdir -p "$ICON_DIR" "$APP_DIR"

# Jangan bikin duplikat: bila paket .deb sudah memasang entri sistem, lewati.
if grep -rqs "StartupWMClass=$APP_ID" /usr/share/applications/ 2>/dev/null; then
  echo "Entri sistem untuk '$APP_ID' sudah terpasang (mis. dari paket .deb); tidak perlu skrip ini."
  exit 0
fi

# Bersihkan percobaan lama bila ada.
rm -f "$APP_DIR/id.appsec.scanner.desktop" "$ICON_DIR/id.appsec.scanner.png"

if command -v magick >/dev/null 2>&1; then
  magick -background none "$ICON_SRC" -resize 256x256 "$ICON_PNG"
else
  cp "$REPO/src-tauri/icons/128x128@2x.png" "$ICON_PNG"
fi

cat > "$APP_DIR/$APP_ID.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=$NAME
Comment=Pemindai keamanan aplikasi — menelusuri jejak, menemukan celah
Exec=$BIN
Icon=$ICON_PNG
Terminal=false
Categories=Development;Security;
StartupWMClass=$APP_ID
EOF

command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$APP_DIR" >/dev/null 2>&1 || true
command -v gtk-update-icon-cache  >/dev/null 2>&1 && gtk-update-icon-cache -f "$HOME/.local/share/icons/hicolor" >/dev/null 2>&1 || true

echo "Terpasang untuk app-id '$APP_ID':"
echo "  $APP_DIR/$APP_ID.desktop"
echo "  $ICON_PNG"
echo "Tutup lalu buka lagi aplikasinya; bila dock belum berubah, logout/login sekali."
