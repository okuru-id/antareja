# PRD — AppSec Scanner Desktop (Tauri 2)

Nov 5, 2026 · Penyusun: @kurob asgari

## Ringkasan Eksekutif

AppSec Scanner adalah aplikasi desktop (Tauri 2 + Rust) untuk menilai keamanan aplikasi yang tim bangun dan deploy sendiri, tanpa perlu jadi pentester profesional. Tool ini menjawab dua pertanyaan nyata: *"Apakah setup deploy publik saya aman?"* dan *"Apakah ada lubang yang terlihat di source code kami?"*

Tool bekerja dalam dua mode yang menyatu di satu aplikasi:

- **Black-box (DAST)** — menilai aplikasi yang sudah live dari luar, seperti yang dilihat penyerang: security headers, konfigurasi TLS, port yang nganga, dan file sensitif yang bocor. Engine native Rust, tanpa dependency berat.
- **White-box (SAST)** — membedah source code dari dalam: bug keamanan (SQLi, XSS), kredensial yang ter-commit, dan dependency yang rentan. Menggunakan scanner open-source matang (Semgrep, Gitleaks, Trivy) sebagai sidecar.

Hasil dari kedua mode masuk ke satu **view temuan terpadu** (diurut per severity) dan bisa diekspor jadi **laporan** rapi. Scope sengaja difokuskan ke **Level 1–2** (posture & automated scanning) — cakupan dengan ROI tertinggi dan paling bisa diotomasi, cocok untuk tim yang baru di AppSec. Target rilis awal **Linux (Ubuntu)**, dengan arsitektur yang disiapkan untuk cross-platform.

## Latar Belakang & Masalah

Tim sering mem-deploy aplikasi ke publik, tapi tidak punya cara terstruktur untuk memastikan setup-nya aman saat diakses dari luar. Pengecekan dilakukan ad-hoc atau tidak sama sekali, sehingga kesalahan konfigurasi umum berisiko lolos ke produksi.

Masalah yang paling sering terjadi di dunia nyata justru bukan exploit canggih, melainkan hal mendasar:

- Database atau cache (Redis, MongoDB, Postgres) terekspos ke publik tanpa autentikasi.
- File sensitif ter-serve: `.env`, folder `.git/`, backup `.sql`, `phpinfo.php`.
- Mode debug menyala di produksi (`APP_DEBUG=true` di Laravel), membocorkan stack trace & konfigurasi.
- Security headers (HSTS, CSP, X-Frame-Options) tidak terpasang.
- Kredensial hardcoded yang tidak sengaja ter-commit ke repository.

Menutup kelas masalah ini saja sudah menyingkirkan sebagian besar risiko nyata. Namun tool komersial AppSec umumnya mahal, kompleks, dan berbasis cloud (source code harus di-upload) — kurang cocok untuk konteks internal BUMN/enterprise di mana kode tidak boleh keluar.

**Kebutuhannya:** satu tool desktop yang berjalan lokal, memeriksa aset milik tim sendiri (live deployment & source code), dan bisa diintegrasikan ke workflow DevOps/CI/CD yang sudah ada — tanpa mengirim data ke pihak ketiga.

## Tujuan & Non-Tujuan

### Tujuan

- Memberi tim cara cepat & berulang untuk memeriksa keamanan deployment publik dari luar (DAST).
- Memberi tim cara memindai source code untuk bug, secret, dan dependency rentan tanpa kode keluar dari mesin (SAST).
- Menyatukan temuan dari kedua mode dalam satu tampilan yang diurut per severity.
- Menghasilkan laporan yang bisa dibagikan ke tim atau atasan.
- Menjadi alat belajar: tiap temuan menjelaskan *apa, kenapa berbahaya, dan cara memperbaiki*, sehingga tim naik skill AppSec sambil memakainya.
- Berjalan lokal di Linux (Ubuntu), dengan basis kode yang siap diperluas ke Windows & macOS.

### Non-Tujuan (tegas di luar scope)

- **Bukan exploitation tool.** Tidak menembus, tidak menjalankan payload, tidak pivot. Hanya menilai, tidak menyerang.
- **Bukan pengganti pentest manual (Level 3–4).** Logic flaw, auth bypass berbasis alur bisnis, dan IDOR kompleks tetap butuh mata manusia — tool tidak mengklaim menemukan itu.
- **Bukan scanner untuk target milik orang lain.** Hanya untuk aset yang dimiliki atau diotorisasi tim.
- **Bukan membangun engine SAST/scanner dari nol.** Memanfaatkan OSS matang; tim membangun lapisan orkestrasi & UX di atasnya.
- **Bukan security monitoring real-time / SIEM.** Ini tool on-demand & CI, bukan pemantauan berkelanjutan.

## Pengguna & Use Case

**Pengguna primer:** DevOps / developer dalam tim yang mem-build & men-deploy aplikasi sendiri, baru di AppSec, dan butuh pengecekan andal tanpa keahlian pentest mendalam.

**Pengguna sekunder:** lead/manajer teknis yang perlu laporan ringkas status keamanan aplikasi tim.

Skenario pemakaian utama:

| # | Use case | Mode | Hasil yang diharapkan |
| --- | --- | --- | --- |
| 1 | Cek keamanan aplikasi sebelum go-live | DAST | Daftar temuan konfigurasi + severity sebelum rilis |
| 2 | Audit berkala deployment yang sudah live | DAST | Perbandingan dengan scan sebelumnya |
| 3 | Review source code sebelum merge/release | SAST | Bug & secret ditunjuk per file:baris |
| 4 | Cek dependency rentan setelah update library | SAST | Daftar CVE pada dependency |
| 5 | Susun laporan keamanan untuk atasan/klien | Report | Dokumen PDF/HTML rapi |
| 6 | Integrasi ke pipeline GitLab CI | CLI/headless | Scan otomatis tiap deploy, gagal bila ada Critical |

## Konsep Inti

Satu aplikasi, dua cara memandang keamanan yang saling melengkapi, bermuara di satu tempat.

&#91;embedded content: alur dua mode · DAST + SAST → temuan terpadu\]

DAST menilai dari luar tanpa akses kode; SAST membedah dari dalam. Keduanya bertemu di view temuan terpadu, lalu diekspor jadi laporan.

## Functional Requirements

Dikelompokkan per modul. Prioritas: **P0** = MVP wajib, **P1** = penting, **P2** = lanjutan.

### FR-1 Manajemen Target & Scope (P0)

- Mendaftarkan target (domain/URL untuk DAST, folder project untuk SAST) ke dalam daftar terkelola.
- Setiap target punya label kepemilikan; scan hanya berjalan pada target terdaftar (guardrail, lihat bagian Keamanan & Etika).
- Menyimpan daftar target antar sesi (persisten lokal).

### FR-2 Mode Black-box / DAST (P0)

- **Security headers** — ambil response, periksa HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy.
- **TLS/HTTPS** — cek versi protokol (tandai TLS 1.0/1.1), masa berlaku & validitas sertifikat, redirect HTTP→HTTPS.
- **Port scan** — TCP connect scan pada port umum berisiko (DB 3306/5432/27017, Redis 6379, panel admin), dengan daftar port yang dapat dikonfigurasi.
- **File & path sensitif** — probe `.env`, `.git/config`, `.sql`, `phpinfo.php`, directory listing, indikasi debug mode aktif.
- **Mode online opsional (P2)** — panggil API SSL Labs / Mozilla Observatory untuk second opinion; non-aktif secara default, hormati rate limit.

### FR-3 Mode White-box / SAST (P0)

- **Pemindaian kode** — jalankan Semgrep pada folder project; parse output JSON jadi temuan ter-normalisasi.
- **Deteksi secret** — jalankan Gitleaks untuk kredensial/token yang ter-commit.
- **Dependency rentan** — jalankan Trivy (mode filesystem) pada manifest (`composer.lock`, `package-lock.json`, dll).
- Tiap temuan menunjuk **file & nomor baris** persis.
- Deteksi otomatis bahasa/stack project untuk memilih rule set yang relevan.

### FR-4 View Temuan Terpadu (P0)

- Semua temuan (DAST + SAST) masuk satu tampilan, diurut per severity: Critical → High → Medium → Low → Info.
- Tiap temuan menampilkan: judul, severity, lokasi (URL atau file:baris), deskripsi, dampak, dan rekomendasi perbaikan.
- Filter berdasarkan mode, severity, dan target.
- Tandai status temuan: Open / Fixed / Accepted Risk / False Positive (P1).

### FR-5 Laporan (P1)

- Ekspor temuan jadi laporan PDF dan/atau HTML.
- Ringkasan eksekutif (jumlah per severity) + detail per temuan.
- Metadata: target, tanggal scan, cakupan.

### FR-6 Korelasi DAST↔SAST (P2)

- Jika SAST menandai endpoint rentan dan DAST mengonfirmasi dari luar, temuan ditandai *terkonfirmasi* dan dinaikkan prioritasnya.

### FR-7 Mode Headless / CLI (P1)

- Jalankan scan tanpa GUI untuk integrasi GitLab CI, keluarkan hasil JSON, kembalikan exit code non-zero bila ditemukan severity di atas ambang tertentu.

## Tech Stack

### Inti

| Lapisan | Pilihan | Catatan |
| --- | --- | --- |
| Shell desktop | **Tauri 2** | Ringan, aman, cross-platform; sudah familiar bagi tim |
| Bahasa backend | **Rust** | Engine scan, orkestrasi, logika bisnis |
| Frontend/UI | Web (React/Svelte/Vue — pilih yang tim kuasai) | Di-render dalam webview Tauri |
| Window frame | **Custom (decorations: false)** | Title bar & kontrol jendela dibuat sendiri, bukan bawaan OS — lihat catatan di bawah |
| Penyimpanan | SQLite (via `sqlx` / `rusqlite`) | Daftar target, riwayat scan, temuan |

### Crate Rust utama

- `reqwest` — HTTP client untuk cek header & probe file.
- `tokio` — async runtime; port scan & scan paralel.
- `rustls` / `tokio-rustls` — inspeksi TLS & sertifikat tanpa OpenSSL (lebih mudah cross-platform).
- `x509-parser` — baca detail sertifikat.
- `serde` / `serde_json` — serialisasi & parse output scanner.
- `sqlx` atau `rusqlite` — akses SQLite.
- `thiserror` / `anyhow` — error handling idiomatik.
- `tracing` — logging terstruktur.

### Sidecar (binary eksternal yang di-bundle)

- **Semgrep** — SAST, bug keamanan di kode.
- **Gitleaks** — deteksi secret (binary Go tunggal, ringan).
- **Trivy** — dependency & image scanning.
- **nuclei** *(opsional, P2)* — template-based vuln scanning untuk jembatan ke Level 2 DAST.

Sidecar dikelola lewat mekanisme sidecar Tauri; engine native Rust tetap jadi inti agar DAST tidak bergantung pada binary luar.

### Catatan custom window frame

- Set `decorations: false` pada konfigurasi window Tauri; title bar, tombol minimize/maximize/close, dan area drag dibuat di frontend.
- Sediakan region drag (`data-tauri-drag-region`) dan command untuk minimize/maximize/close.
- **Lintas platform:** perilaku frameless berbeda antar OS (snap layout Windows, traffic light macOS). Untuk rilis Ubuntu-first ini tidak masalah; saat ekspansi, kontrol jendela perlu disesuaikan per platform — dicatat sebagai titik perhatian cross-platform.

## Arsitektur & Clean Code

Mengikuti prinsip clean architecture: lapisan luar bergantung ke dalam, dan inti (Domain) tidak tahu apa-apa soal UI, Tauri, atau SQLite.

&#91;embedded content: arsitektur berlapis · dependency inversion lewat trait\]

Kunci dari **repository pattern** di sini: Domain mendefinisikan *trait* (`TargetRepository`, `ScanRepository`, dan trait scanner), lalu Infra & Scanner meng-implementasikannya. Use case hanya bergantung pada trait — bukan pada SQLite atau binary sidecar. Efeknya: inti bisa di-unit-test dengan mock, implementasi bisa diganti, dan `core` yang sama dipakai ulang oleh GUI *dan* CLI headless.

Penerapan clean code lain: error handling eksplisit (`Result`), `clippy` + `rustfmt` di CI, dan command Tauri dibuat setipis mungkin (hanya delegasi ke use case).

## Struktur Proyek

Menggunakan **Cargo workspace** agar engine terpisah dari shell Tauri — ini yang membuat mode headless/CLI (FR-7) dan pengujian jadi mudah: logika inti tidak bergantung pada Tauri.

```
appsec-scanner/
├─ crates/
│  ├─ core/                 # domain + logika, TANPA dependensi Tauri
│  │  ├─ domain/            # entitas & trait (Finding, Severity, Target, repository traits)
│  │  ├─ usecase/           # application services (orkestrasi scan, dedup, korelasi)
│  │  ├─ scanner/           # implementasi scanner
│  │  │  ├─ dast/           # headers, tls, ports, files (native Rust)
│  │  │  └─ sast/           # adapter Semgrep, Gitleaks, Trivy (sidecar)
│  │  └─ infra/             # implementasi repository (SQLite), file system, proses sidecar
│  └─ cli/                  # entry point headless untuk CI (pakai core)
├─ src-tauri/                # shell desktop: Tauri commands, window, sidecar config
│  └─ src/
│     ├─ commands/          # #[tauri::command] tipis, delegasi ke usecase
│     └─ main.rs
├─ ui/                       # frontend (React/Svelte/Vue), termasuk custom title bar
└─ Cargo.toml                # definisi workspace
```

Prinsip pemisahan:

- **`core`** tidak tahu apa-apa soal Tauri maupun UI — bisa dikompilasi & diuji sendiri, dipakai ulang oleh GUI *dan* CLI.
- **`src-tauri`** hanya lem tipis: menerima perintah dari UI, memanggil use case, mengembalikan hasil.
- Scanner dan repository diakses lewat **trait** (lihat bagian Arsitektur), jadi mudah di-mock saat testing dan diganti implementasinya.

## Model Data

Entitas domain inti (di `core/domain`), independen dari penyimpanan maupun UI.

```rust
enum Severity { Critical, High, Medium, Low, Info }
enum ScanMode { Dast, Sast }
enum FindingStatus { Open, Fixed, AcceptedRisk, FalsePositive }

struct Target {
    id: Uuid,
    kind: TargetKind,      // Url(host) | SourcePath(path)
    label: String,
    owned: bool,           // guardrail kepemilikan
    created_at: DateTime,
}

struct Finding {
    id: Uuid,
    scan_id: Uuid,
    mode: ScanMode,
    severity: Severity,
    title: String,
    location: String,      // URL atau "file.php:42"
    description: String,
    impact: String,
    recommendation: String,
    status: FindingStatus,
    rule_id: Option<String>,   // id rule Semgrep/Trivy, untuk korelasi
}

struct Scan {
    id: Uuid,
    target_id: Uuid,
    mode: ScanMode,
    started_at: DateTime,
    finished_at: Option<DateTime>,
    findings: Vec<Finding>,
}
```

### Repository traits (domain)

Kontrak penyimpanan didefinisikan sebagai trait di domain; implementasinya (SQLite) ada di `infra`. Ini inti dari repository pattern — use case bergantung pada trait, bukan pada SQLite.

```rust
trait TargetRepository {
    async fn add(&self, target: Target) -> Result<()>;
    async fn list(&self) -> Result<Vec<Target>>;
    async fn get(&self, id: Uuid) -> Result<Option<Target>>;
    async fn remove(&self, id: Uuid) -> Result<()>;
}

trait ScanRepository {
    async fn save(&self, scan: Scan) -> Result<()>;
    async fn history(&self, target_id: Uuid) -> Result<Vec<Scan>>;
}
```

### Penyimpanan

SQLite lokal, tabel: `targets`, `scans`, `findings`. Output mentah scanner disimpan sementara, lalu dinormalisasi ke `Finding` sebelum ditampilkan/diekspor.

## Keamanan, Etika & Kontrol Scope

Tool ini menilai, bukan menyerang — tapi memindai aset milik orang lain tetap bisa ilegal. Guardrail dibangun agar pemakaian tetap pada aset sendiri/terotorisasi:

- **Daftar target terdaftar.** Scan hanya berjalan pada target yang sudah didaftarkan & ditandai dimiliki/diotorisasi; tidak ada "scan sembarang host" tanpa pendaftaran.
- **Konfirmasi kepemilikan.** Saat menambah target DAST, tampilkan pengingat bahwa pengguna bertanggung jawab atas izin.
- **Scan non-intrusif.** DAST hanya kirim request & TCP connect biasa; tanpa exploit, brute-force, atau DoS. Hormati rate yang wajar.
- **Tidak ada data keluar.** SAST murni lokal; mode online (SSL Labs, dll) opsional, non-aktif default, dan diberi disclaimer rate limit/ToS.
- **Penyimpanan temuan sensitif.** Temuan bisa memuat info sensitif (secret yang bocor); simpan lokal, pertimbangkan enkripsi at-rest untuk database temuan.

> **Catatan:** untuk konteks enterprise/BUMN, sebaiknya ada persetujuan tertulis internal sebelum menjadikan tool ini bagian resmi dari proses rilis. Ini melindungi tim secara prosedural, bukan hanya teknis.

## Non-Functional Requirements

- **Performa.** Scan DAST & SAST berjalan async/paralel tanpa membekukan UI; progress tampil real-time. Port scan dibatasi concurrency agar tidak membanjiri target.
- **Cross-platform ready.** Rilis awal Ubuntu, tapi hindari dependensi Linux-only. Pilih `rustls` (bukan OpenSSL sistem) dan abstraksi proses sidecar agar port ke Windows/macOS minim perubahan. Titik yang perlu disesuaikan saat ekspansi: kontrol custom window frame & path binary sidecar.
- **Keandalan.** Kegagalan satu modul scan tidak menggagalkan seluruh sesi; error per-modul dilaporkan, hasil parsial tetap tampil.
- **UX.** Alur jelas: pilih target → jalankan → lihat temuan → ekspor. Custom window frame (sesuai permintaan) harus tetap mendukung drag, resize, dan kontrol jendela standar. Mendukung tema terang/gelap.
- **Clean code & testability.** `core` punya unit test; scanner & repository di-mock lewat trait. Terapkan `clippy` + `rustfmt` di CI.
- **Keamanan aplikasi sendiri.** Validasi input target, kelola binary sidecar dengan aman (verifikasi checksum), batasi permission Tauri (allowlist) seperlunya.

## Roadmap Fase

Urutan dipilih agar tiap fase memberi hasil pakai nyata, dimulai dari yang paling simpel secara teknis.

| Fase | Fokus | Deliverable | Kriteria selesai |
| --- | --- | --- | --- |
| **F0 — Fondasi** | Workspace & arsitektur | Cargo workspace, domain + trait, SQLite, shell Tauri + custom window frame | App jalan, bisa daftar target & simpan |
| **F1 — SAST (MVP)** | Mode white-box | Integrasi Semgrep + Gitleaks + Trivy, view temuan terpadu | Drag folder → temuan muncul per file:baris |
| **F2 — DAST** | Mode black-box | Engine native: headers, TLS, port, file sensitif | Input domain → temuan konfigurasi muncul |
| **F3 — Laporan** | Output | Ekspor PDF/HTML + ringkasan per severity | Laporan bisa dibagikan |
| **F4 — CI & status** | Integrasi | Mode headless/CLI untuk GitLab, status temuan | Scan otomatis di pipeline, gagal bila Critical |
| **F5 — Lanjutan (P2)** | Kedalaman | nuclei, mode online, korelasi DAST↔SAST | Jembatan ke Level 2 aktif |

Rekomendasi titik mulai: **F0 → F1**. SAST paling simpel (tanpa urusan jaringan/scope) dan langsung memberi hasil nyata pada kode tim di hari pertama.

## Risiko & Mitigasi

| Risiko | Dampak | Mitigasi |
| --- | --- | --- |
| Bundling & update sidecar (Semgrep/Trivy) rumit | Build berat, versi tool usang | Pin versi, verifikasi checksum, mekanisme update terpisah dari app |
| False positive menurunkan kepercayaan tim | Temuan diabaikan | Pakai rule matang, sediakan status "False Positive", tampilkan konteks |
| Tim mengira tool = jaminan aman penuh | Rasa aman palsu (Level 3 lolos) | Nyatakan batas scope eksplisit di UI & laporan |
| Scan tak sengaja ke target orang lain | Masalah hukum/etika | Guardrail daftar target + konfirmasi kepemilikan |
| Perbedaan perilaku frameless window antar OS | Hambatan cross-platform | Isolasi kode window, tangani per platform saat ekspansi |
| Scope membengkak (ingin semua sekaligus) | MVP tak kunjung jadi | Patuhi prioritas P0→P2 & roadmap fase |

## Metrik Sukses

- **Adopsi:** tool dipakai pada setiap rilis aplikasi tim sebelum go-live.
- **Temuan tertangani:** jumlah misconfigurasi & secret bocor yang ditemukan dan diperbaiki sebelum produksi.
- **Cakupan:** proporsi aplikasi/repo tim yang sudah di-scan minimal sekali.
- **Integrasi CI:** jumlah pipeline yang menjalankan scan otomatis.
- **Peningkatan skill:** tim mampu membaca & menindaklanjuti temuan tanpa bantuan eksternal (indikator kualitatif).

## Glosarium

| Istilah | Arti singkat |
| --- | --- |
| **AppSec** | Application Security — keamanan di level aplikasi |
| **DAST** | Dynamic Application Security Testing — menguji aplikasi yang sedang berjalan dari luar |
| **SAST** | Static Application Security Testing — menganalisis source code tanpa menjalankannya |
| **Black-box** | Pengujian tanpa akses internal, hanya dari luar |
| **White-box** | Pengujian dengan akses penuh ke source code |
| **Severity** | Tingkat keparahan temuan (Critical–Info) |
| **False positive** | Temuan yang ditandai scanner tapi sebenarnya bukan masalah |
| **CVE** | Common Vulnerabilities and Exposures — ID standar kerentanan publik |
| **HSTS / CSP** | Security headers untuk memaksa HTTPS & membatasi sumber konten |
| **Sidecar** | Binary eksternal yang dibundel & dipanggil oleh aplikasi utama |
| **Repository pattern** | Pola yang memisahkan logika dari penyimpanan lewat antarmuka (trait) |
