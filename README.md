# Antareja

*Menelusuri jejak, menemukan celah.*

Aplikasi desktop (Tauri 2 + Rust + Vue/shadcn-vue) untuk scan keamanan aset milik tim sendiri. Nama & branding: lihat [DESIGN.md](DESIGN.md). Lihat juga PRD.

## Setup (Ubuntu)

```bash
scripts/fetch-sidecars.sh        # gitleaks + trivy + nuclei (versi di-pin, checksum diverifikasi) -> src-tauri/binaries/
uv tool install semgrep          # semgrep tidak di-bundle (aplikasi Python), harus ada di PATH
npm --prefix ui install
cd src-tauri && cargo tauri dev
```

Catatan: Semgrep mengunduh rule pack dan Trivy mengunduh DB kerentanan saat dijalankan (butuh internet). Source code tidak dikirim ke mana pun.

## CLI / CI

```bash
cargo run -p appsec-cli -- scan <folder|url> [--format text|json|md] [--fail-on critical|high|medium|low|info|none] [--authorized] [--nuclei] [--online]
```

- Exit code: `0` lolos, `1` ada temuan dengan severity ≥ `--fail-on` (default `critical`), `2` error atau ada modul scan yang gagal.
- Target URL wajib `--authorized` (pernyataan target milik sendiri / ada izin tertulis).
- `--nuclei` (template nuclei non-intrusif, lambat) dan `--online` (Mozilla HTTP Observatory, hostname dikirim ke pihak ketiga) opsional; di GUI ada toggle di tab Target.
- Progress & ringkasan ke stderr, hasil ke stdout.

GitLab CI: build image dari [ci/Dockerfile](ci/Dockerfile) (`docker build -f ci/Dockerfile -t appsec-scanner .`), push ke registry internal, lalu pakai job di [ci/gitlab-ci.example.yml](ci/gitlab-ci.example.yml).
