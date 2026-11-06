# Branding — Antareja

**Menelusuri jejak, menemukan celah.**

## Nama

**Antareja** — putra Bima dalam pewayangan yang mampu *mendeteksi*: merasakan ancaman lewat tanah dan mengenali siapa pun dari jejaknya. Metafora tepat untuk pemindai keamanan — menelusuri jejak aplikasi, menemukan celah sebelum disalahgunakan. Dualitas bisa/penawar-nya selaras dengan mode **defensif vs intrusif** aplikasi.

- Identifier teknis tetap `id.appsec.scanner` (jangan diubah — menentukan folder data, DB, dan tool terpasang).
- Nama produk / judul window / UI: **Antareja**.

## Logo

Perisai (perlindungan) berisi **radar** (deteksi) dengan beam menyapu dan satu *blip* — menyatukan makna "menjaga" dan "menelusuri jejak", sekaligus konsisten dengan animasi radar di layar Progres pemindaian.

- Sumber: [`ui/src/assets/antareja.svg`](ui/src/assets/antareja.svg).
- Ikon aplikasi (ico/icns/png) di-generate dari logo itu via `cargo tauri icon`.
- Di title bar logo dipakai apa adanya; tetap terbaca kecil (16px) sebagai perisai biru.

## Warna

| Token | Nilai | Pakai |
|---|---|---|
| Primer | biru (`--primary`, ~`#2563eb`) | brand, aksi, radar aktif |
| Scope radar | navy (`#0d2152`–`#16337a`) | latar radar/logo |
| Aksen sweep | cyan muda (`#7dd3fc`/`#e0f2fe`) | beam & blip radar |

Severity (jangan diubah — sudah baku): **merah** Critical/High · **amber** Medium · **biru/abu** Low · **abu** Info.

## Tipografi

**Geist** (sudah di-bundle lokal via `@fontsource`). Nama produk di-set `font-semibold tracking-tight`.

## Tone / voice

Teknikal, tenang, jelas — asisten keamanan developer, bukan alarm. Hindari bahasa menakut-nakuti. Contoh yang sudah sesuai: *"Hasil scan ini dibuang; data scan sebelumnya tetap dipakai."*
