//! Tool eksternal: lokasi binary, konfigurasi per tool, versi terpasang, dan update mandiri.
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{OnceLock, RwLock};

/// Konfigurasi per tool (setting key "tools"). Field baru wajib punya default agar setting lama tetap terbaca.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ToolOptions {
    /// Rule pack Semgrep tambahan, mis. "p/owasp-top-ten".
    pub semgrep_extra: Vec<String>,
    /// Path/pola yang tidak dipindai Semgrep (`--exclude`), mis. "tests", "*.min.js".
    pub semgrep_exclude: Vec<String>,
    /// Gitleaks: pindai seluruh riwayat commit (bukan hanya file saat ini).
    pub gitleaks_history: bool,
    /// Trivy: hanya CVE yang sudah ada versi perbaikannya.
    pub trivy_ignore_unfixed: bool,
    /// Trivy: cek salah konfigurasi IaC (Dockerfile, Kubernetes, Terraform, Compose).
    pub trivy_misconfig: bool,
    /// Trivy: lisensi dependency berisiko (kategori forbidden/restricted).
    pub trivy_license: bool,
    pub nuclei_tags: String,
    /// Request per detik ke target.
    pub nuclei_rate: u32,
    /// Crawl dengan Katana dulu, lalu cek exposure di direktori yang ditemukan (butuh Katana terpasang).
    pub nuclei_crawl: bool,
    /// Domain dev yang boleh dipindai modul intrusif selain localhost ("dev.app.com", "*.dev.app.com").
    pub intrusive_hosts: Vec<String>,
    /// Request per detik untuk modul intrusif.
    pub intrusive_rate: u32,
}

impl Default for ToolOptions {
    fn default() -> Self {
        Self {
            semgrep_extra: vec![],
            semgrep_exclude: vec![],
            gitleaks_history: true,
            trivy_ignore_unfixed: false,
            trivy_misconfig: true,
            trivy_license: true,
            nuclei_tags: "exposure,misconfig,config,cve,panel".into(),
            nuclei_rate: 50,
            nuclei_crawl: true,
            intrusive_hosts: vec![],
            intrusive_rate: 20,
        }
    }
}

static TOOLS_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Folder binary hasil update (data aplikasi, bisa ditulis). Diset sekali saat aplikasi mulai.
pub fn set_dir(dir: PathBuf) {
    let _ = TOOLS_DIR.set(dir);
}

// Token GitHub login (dari UI); menaikkan limit API GitHub 60/jam -> 5000/jam.
static GITHUB_TOKEN: RwLock<Option<String>> = RwLock::new(None);

/// Simpan token GitHub aktif (None = logout). Dipanggil saat start & setiap login/logout.
pub fn set_github_token(token: Option<String>) {
    *GITHUB_TOKEN.write().unwrap() = token.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
}

/// Token aktif: hasil login di UI, atau fallback variabel lingkungan.
fn github_token() -> Option<String> {
    GITHUB_TOKEN.read().unwrap().clone()
        .or_else(|| std::env::var("GITHUB_TOKEN").or_else(|_| std::env::var("GH_TOKEN")).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Validasi token GitHub lalu kembalikan username-nya. Dipakai command login.
pub fn github_login(token: &str) -> Result<String> {
    let token = token.trim();
    anyhow::ensure!(!token.is_empty(), "Token kosong");
    let resp = reqwest::blocking::Client::builder()
        .user_agent("appsec-scanner")
        .timeout(std::time::Duration::from_secs(15))
        .build()?
        .get("https://api.github.com/user")
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
        .send()?;
    anyhow::ensure!(resp.status().as_u16() != 401, "Token GitHub tidak valid atau kedaluwarsa");
    let v: serde_json::Value = serde_json::from_slice(&resp.error_for_status()?.bytes()?)?;
    v["login"].as_str().map(String::from).context("Respons GitHub tidak memuat username")
}

/// Tool tersedia: hasil update/sidecar, atau ada di PATH.
pub fn installed(name: &str) -> bool {
    let p = bin(name);
    p.is_absolute() || std::env::var_os("PATH").is_some_and(|path| std::env::split_paths(&path).any(|d| d.join(name).is_file()))
}

fn which(name: &Path) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?).map(|d| d.join(name)).find(|p| p.is_file())
}

/// Cari binary: hasil update -> di samping executable (sidecar Tauri) -> PATH.
pub fn bin(name: &str) -> PathBuf {
    // Hanya untuk mencari sidecar; tidak dipakai untuk keputusan keamanan.
    // nosemgrep: rust.lang.security.current-exe.current-exe
    let next_to_exe = std::env::current_exe().ok().and_then(|e| Some(e.parent()?.join(name)));
    TOOLS_DIR.get().map(|d| d.join(name)).into_iter().chain(next_to_exe)
        .find(|p| p.is_file())
        .unwrap_or_else(|| name.into())
}

#[derive(Debug, Serialize)]
pub struct ToolInfo {
    pub id: String,
    /// None = tidak ditemukan.
    pub version: Option<String>,
    /// Info data: tanggal DB CVE (Trivy) / versi template (Nuclei).
    pub data: Option<String>,
    /// "update" (hasil update di app), "bawaan" (sidecar), "sistem" (PATH).
    pub source: &'static str,
}

pub const TOOLS: &[&str] = &["semgrep", "gitleaks", "trivy", "nuclei", "katana", "testssl", "nmap", "zap", "ffuf", "dalfox", "sqlmap"];

/// Skrip ZAP: hasil pasang di app -> lokasi instalasi umum -> PATH.
pub fn zap() -> Option<PathBuf> {
    let own = TOOLS_DIR.get().map(|d| d.join("zap").join("zap.sh"));
    own.into_iter()
        .chain(["/opt/zaproxy/zap.sh", "/usr/share/zaproxy/zap.sh", "/Applications/ZAP.app/Contents/Java/zap.sh"].map(PathBuf::from))
        .find(|p| p.is_file())
        .or_else(|| which(Path::new("zap.sh")))
}

/// JAVA_HOME hasil pasang di app (None = pakai Java sistem).
pub fn java_home() -> Option<PathBuf> {
    let jre = TOOLS_DIR.get()?.join("jre");
    jre.join("bin").join("java").is_file().then_some(jre)
}

/// Versi mayor Java (17, 21, ...) dari JRE app atau sistem.
fn java_major() -> Option<u32> {
    let java = java_home().map_or(PathBuf::from("java"), |h| h.join("bin").join("java"));
    let o = Command::new(java).arg("-version").output().ok()?;
    let t = String::from_utf8_lossy(&o.stderr);
    let v = t.split('"').nth(1)?;
    v.split('.').next()?.parse().ok()
}

/// testssl.sh tidak merilis checksum: versi dipin dengan SHA-256 arsip tag yang sudah diverifikasi.
const TESTSSL_VERSION: &str = "3.2.5";
const TESTSSL_SHA256: &str = "23bb53d50ae093b89631e9fff547c087f632bf35f7a3d7dc78dd4ffff56cd779";

/// Skrip testssl.sh: hasil pasang di app (folder lengkap dengan data & openssl bawaan) -> PATH.
pub fn testssl() -> Option<PathBuf> {
    let own = TOOLS_DIR.get().map(|d| d.join("testssl").join("testssl.sh")).filter(|p| p.is_file());
    own.or_else(|| ["testssl.sh", "testssl"].into_iter().find(|n| installed(n)).map(PathBuf::from))
}

/// Output gabungan stdout+stderr (nuclei menulis versi ke stderr), tanpa kode warna ANSI.
fn output(name: &str, args: &[&str]) -> Option<String> {
    let o = Command::new(bin(name)).args(args).output().ok()?;
    let text = String::from_utf8_lossy(&o.stdout).into_owned() + &String::from_utf8_lossy(&o.stderr);
    Some(crate::sast::strip_ansi(&text))
}

/// Angka versi pertama setelah `marker` (mis. "Version: 0.76.1" -> "0.76.1").
fn after(text: &str, marker: &str) -> Option<String> {
    let rest = &text[text.find(marker)? + marker.len()..];
    Some(rest.trim_start().trim_start_matches('v').split_whitespace().next()?.to_string())
}

pub fn info(id: &str) -> ToolInfo {
    let path = match id {
        "testssl" => testssl().unwrap_or_else(|| id.into()),
        "zap" => zap().unwrap_or_else(|| id.into()),
        _ => bin(id),
    };
    let source = if TOOLS_DIR.get().is_some_and(|d| path.starts_with(d)) {
        "update"
    } else if path.is_absolute() {
        "bawaan"
    } else {
        "sistem"
    };
    let (version, data) = match id {
        "semgrep" => (output(id, &["--version", "--disable-version-check"]).and_then(|t| t.lines().next().map(|l| l.trim().to_string())), None),
        "gitleaks" => (output(id, &["version"]).map(|t| t.trim().trim_start_matches('v').to_string()), None),
        "trivy" => {
            let t = output(id, &["--version"]);
            let ver = t.as_deref().and_then(|t| after(t, "Version:"));
            // "UpdatedAt: 2026-11-05 01:19:45 ..." -> tanggal saja
            let db = t.as_deref().and_then(|t| after(t, "UpdatedAt:")).map(|d| format!("DB CVE {d}"));
            (ver, db.or(Some("DB CVE belum diunduh".into())))
        }
        "nuclei" => {
            let ver = output(id, &["-version", "-duc"]).and_then(|t| after(&t, "Engine Version:"));
            let tpl = output(id, &["-templates-version", "-duc"]).and_then(|t| after(&t, "templates version:"));
            (ver, Some(tpl.map_or("Template belum diunduh".into(), |v| format!("Template v{v}"))))
        }
        "katana" => (output(id, &["-version"]).and_then(|t| after(&t, "Current version:")), None),
        "nmap" => (output(id, &["--version"]).and_then(|t| after(&t, "Nmap version")), None),
        "ffuf" => (output(id, &["-V"]).and_then(|t| after(&t, "ffuf version:")).map(|v| v.trim_end_matches("-dev").to_string()), None),
        "dalfox" => (output(id, &["--version"]).and_then(|t| t.split_whitespace().find(|w| w.trim_start_matches('v').starts_with(|c: char| c.is_ascii_digit())).map(|w| w.trim_start_matches('v').to_string())), None),
        "sqlmap" => (output(id, &["--version"]).map(|t| t.trim().split('#').next().unwrap_or_default().to_string()), None),
        "zap" => {
            let ver = zap().and_then(|p| std::fs::read_to_string(p.with_file_name(".appsec-version")).ok().map(|v| v.trim().to_string())
                .or_else(|| {
                    let o = Command::new("bash").arg(&p).arg("-version").env("JAVA_HOME", java_home().unwrap_or_default()).output().ok()?;
                    String::from_utf8_lossy(&o.stdout).lines().rev().find(|l| l.chars().next().is_some_and(|c| c.is_ascii_digit())).map(|l| l.trim().to_string())
                }));
            let java = match java_major() {
                Some(v) if v >= 17 => format!("Java {v}{}", if java_home().is_some() { " (bawaan app)" } else { "" }),
                Some(v) => format!("Java {v} terlalu lama (butuh 17+)"),
                None => "Java belum ada".into(),
            };
            (ver, Some(java))
        }
        "testssl" => {
            // Versi dibaca dari skrip (menjalankannya lambat).
            let ver = testssl().and_then(|p| {
                let p = if p.is_absolute() { p } else { which(&p)? };
                let text = std::fs::read_to_string(p).ok()?;
                text.lines().find_map(|l| l.split_once("VERSION=\"").map(|(_, r)| r.split('"').next().unwrap_or_default().to_string()))
            });
            (ver, None)
        }
        _ => (None, None),
    };
    ToolInfo { id: id.into(), version: version.filter(|v| !v.is_empty()), data, source }
}

/// Jalankan perintah update; output diteruskan ke `log` baris per baris.
fn run_logged(name: &str, cmd: &Path, args: &[&str], log: &dyn Fn(&str)) -> Result<()> {
    // temp_dir hanya direktori kerja; unduhan disimpan di folder tools aplikasi.
    // nosemgrep: rust.lang.security.temp-dir.temp-dir
    crate::sast::run_path(name, cmd, &std::env::temp_dir(), args, log).map(|_| ())
}

/// Update satu bagian: "semgrep" | "gitleaks" | "trivy" | "nuclei" (program) atau "trivy-db" | "nuclei-templates" (data).
pub fn update(target: &str, log: &dyn Fn(&str)) -> Result<String> {
    match target {
        "semgrep" => {
            // Semgrep aplikasi Python: update lewat installer yang memasangnya.
            let uv = Command::new("uv").args(["tool", "list"]).output().ok()
                .is_some_and(|o| String::from_utf8_lossy(&o.stdout).lines().any(|l| l.starts_with("semgrep ")));
            if uv {
                run_logged("uv", Path::new("uv"), &["tool", "upgrade", "semgrep"], log)?;
            } else if Command::new("pipx").args(["list", "--short"]).output().ok()
                .is_some_and(|o| String::from_utf8_lossy(&o.stdout).lines().any(|l| l.starts_with("semgrep ")))
            {
                run_logged("pipx", Path::new("pipx"), &["upgrade", "semgrep"], log)?;
            } else {
                bail!("Semgrep tidak dipasang lewat uv/pipx; update manual (mis. `uv tool install semgrep`)");
            }
        }
        "trivy-db" => run_logged("trivy", &bin("trivy"), &["fs", "--download-db-only", "--no-progress"], log)?,
        "nuclei-templates" => run_logged("nuclei", &bin("nuclei"), &["-update-templates", "-duc"], log)?,
        "gitleaks" | "trivy" | "nuclei" | "katana" | "ffuf" | "dalfox" => return update_binary(target, log),
        "sqlmap" => {
            // sqlmap aplikasi Python: pasang/upgrade lewat uv (atau pipx); paket diverifikasi hash oleh installer.
            if which(Path::new("uv")).is_some() {
                run_logged("uv", Path::new("uv"), &["tool", "install", "--upgrade", "sqlmap"], log)?;
            } else if which(Path::new("pipx")).is_some() {
                run_logged("pipx", Path::new("pipx"), &["install", "--force", "sqlmap"], log)?;
            } else {
                bail!("Butuh uv atau pipx untuk memasang sqlmap (mis. `curl -LsSf https://astral.sh/uv/install.sh | sh`)");
            }
        }
        "testssl" => return install_testssl(log),
        "zap" => return install_zap(log),
        "nmap" => return install_nmap(log),
        _ => bail!("Tool tidak dikenal: {target}"),
    }
    let i = info(target.split('-').next().unwrap_or_default());
    Ok(format!("Selesai. {}", [i.version.map(|v| format!("versi {v}")), i.data].into_iter().flatten().collect::<Vec<_>>().join(" · ")))
}

fn repo(name: &str) -> &'static str {
    match name {
        "gitleaks" => "gitleaks/gitleaks",
        "trivy" => "aquasecurity/trivy",
        "katana" => "projectdiscovery/katana",
        "ffuf" => "ffuf/ffuf",
        "dalfox" => "hahwul/dalfox",
        _ => "projectdiscovery/nuclei",
    }
}

fn http(secs: u64) -> Result<reqwest::blocking::Client> {
    let mut b = reqwest::blocking::Client::builder()
        .user_agent("appsec-scanner")
        .timeout(std::time::Duration::from_secs(secs));
    // Token GitHub (login UI atau env) menaikkan limit API dari 60/jam jadi 5000/jam.
    if let Some(mut v) = github_token().and_then(|t| reqwest::header::HeaderValue::from_str(&format!("Bearer {t}")).ok()) {
        v.set_sensitive(true);
        let mut h = reqwest::header::HeaderMap::new();
        h.insert(reqwest::header::AUTHORIZATION, v);
        b = b.default_headers(h);
    }
    Ok(b.build()?)
}

fn json(http: &reqwest::blocking::Client, url: &str) -> Result<serde_json::Value> {
    let resp = http.get(url).send()?;
    // 403/429 dari API GitHub = limit terlampaui (60/jam tanpa token).
    if matches!(resp.status().as_u16(), 403 | 429) && url.contains("api.github.com") {
        bail!("GitHub membatasi permintaan API (limit 60/jam tanpa token). Tunggu beberapa saat lalu coba lagi, atau set variabel lingkungan GITHUB_TOKEN agar limitnya jauh lebih tinggi.");
    }
    Ok(serde_json::from_slice(&resp.error_for_status()?.bytes()?)?)
}

fn github_tag(http: &reqwest::blocking::Client, repo: &str) -> Result<String> {
    let rel = json(http, &format!("https://api.github.com/repos/{repo}/releases/latest"))?;
    Ok(rel["tag_name"].as_str().context("tag rilis tidak ditemukan")?.to_string())
}

/// Versi program terbaru yang dirilis (GitHub release / PyPI untuk Semgrep). Butuh internet.
pub fn latest(id: &str) -> Result<String> {
    let http = http(15)?;
    if id == "semgrep" || id == "sqlmap" {
        let v = json(&http, &format!("https://pypi.org/pypi/{id}/json"))?;
        return Ok(v["info"]["version"].as_str().context("versi PyPI tidak ditemukan")?.to_string());
    }
    anyhow::ensure!(TOOLS.contains(&id), "Tool tidak dikenal: {id}");
    match id {
        "testssl" => return Ok(TESTSSL_VERSION.into()),
        "nmap" => bail!("nmap dikelola sistem"),
        "zap" => return Ok(github_tag(&http, "zaproxy/zaproxy")?.trim_start_matches('v').to_string()),
        _ => {}
    }
    Ok(github_tag(&http, repo(id))?.trim_start_matches('v').to_string())
}

fn sha256(path: &Path) -> Result<String> {
    let o = Command::new("sha256sum").arg(path).output().context("sha256sum tidak tersedia")?;
    Ok(String::from_utf8_lossy(&o.stdout).split_whitespace().next().unwrap_or_default().to_string())
}

/// Unduh arsip ke folder sementara di `dir` dan pastikan SHA-256-nya cocok; kembalikan (folder tmp, arsip).
fn download_verified(dir: &Path, key: &str, url: &str, expected: &str, secs: u64, log: &dyn Fn(&str)) -> Result<(PathBuf, PathBuf)> {
    let tmp = dir.join(format!(".tmp-{key}"));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp)?;
    let archive = tmp.join(url.rsplit('/').next().unwrap_or("download"));
    log(&format!("unduh {url}…"));
    let mut resp = http(secs)?.get(url).send()?.error_for_status()?;
    let mut file = std::fs::File::create(&archive)?;
    std::io::copy(&mut resp, &mut file)?;
    let actual = sha256(&archive)?;
    if actual != expected {
        let _ = std::fs::remove_dir_all(&tmp);
        bail!("Checksum tidak cocok: unduhan dibatalkan (harap {expected}, dapat {actual})");
    }
    log("checksum SHA-256 cocok, ekstrak…");
    Ok((tmp, archive))
}

/// Ganti folder `dest` dengan `new` (folder lama dibuang setelahnya).
fn replace_dir(new: &Path, dest: &Path) -> Result<()> {
    let old = dest.with_extension("old");
    let _ = std::fs::remove_dir_all(&old);
    if dest.exists() {
        std::fs::rename(dest, &old)?;
    }
    std::fs::rename(new, dest)?;
    let _ = std::fs::remove_dir_all(&old);
    Ok(())
}

/// ZAP (Linux tar / macOS crossplatform zip, SHA-256 dari GitHub) + JRE Temurin 17 bila Java sistem < 17 (SHA-256 dari API Adoptium).
fn install_zap(log: &dyn Fn(&str)) -> Result<String> {
    let dir = TOOLS_DIR.get().context("folder tools belum diset")?;
    let mac = std::env::consts::OS == "macos";
    anyhow::ensure!(mac || std::env::consts::OS == "linux", "Pemasangan ZAP otomatis hanya untuk Linux/macOS; di OS lain pasang ZAP dari zaproxy.org");
    let http = http(30)?;
    let mut msg = vec![];
    if java_major().is_none_or(|v| v < 17) {
        let arch = if std::env::consts::ARCH == "aarch64" { "aarch64" } else { "x64" };
        let jos = if mac { "mac" } else { "linux" };
        let api = json(&http, &format!("https://api.adoptium.net/v3/assets/latest/17/hotspot?architecture={arch}&image_type=jre&os={jos}&vendor=eclipse"))?;
        let pkg = &api[0]["binary"]["package"];
        let (url, sum) = (pkg["link"].as_str().context("link JRE tidak ada")?, pkg["checksum"].as_str().context("checksum JRE tidak ada")?);
        log("Java 17+ tidak ditemukan: pasang JRE Temurin 17…");
        let (tmp, archive) = download_verified(dir, "jre", url, sum, 600, log)?;
        anyhow::ensure!(Command::new("tar").arg("-xzf").arg(&archive).arg("-C").arg(&tmp).status()?.success(), "ekstrak JRE gagal");
        let root = std::fs::read_dir(&tmp)?.flatten().map(|e| e.path()).find(|p| p.is_dir()).context("isi arsip JRE kosong")?;
        // macOS: struktur JRE adalah <root>/Contents/Home/bin/java.
        let home = if mac { root.join("Contents").join("Home") } else { root };
        replace_dir(&home, &dir.join("jre"))?;
        let _ = std::fs::remove_dir_all(&tmp);
        msg.push("JRE 17 terpasang".to_string());
    }
    let tag = github_tag(&http, "zaproxy/zaproxy")?;
    let v = tag.trim_start_matches('v');
    if info("zap").version.as_deref() == Some(v) && zap().is_some_and(|p| p.starts_with(dir)) {
        msg.push(format!("ZAP sudah versi terbaru ({v})"));
        return Ok(msg.join(" · "));
    }
    let rel = json(&http, &format!("https://api.github.com/repos/zaproxy/zaproxy/releases/tags/{tag}"))?;
    let name = if mac { format!("ZAP_{v}_Crossplatform.zip") } else { format!("ZAP_{v}_Linux.tar.gz") };
    let asset = rel["assets"].as_array().into_iter().flatten().find(|a| a["name"] == name.as_str()).with_context(|| format!("aset {name} tidak ditemukan"))?;
    let sum = asset["digest"].as_str().and_then(|d| d.strip_prefix("sha256:")).context("checksum ZAP tidak tersedia")?;
    let (tmp, archive) = download_verified(dir, "zap", asset["browser_download_url"].as_str().unwrap_or_default(), sum, 1800, log)?;
    let ok = if mac {
        Command::new("unzip").args(["-o", "-q"]).arg(&archive).arg("-d").arg(&tmp).status()
    } else {
        Command::new("tar").arg("-xzf").arg(&archive).arg("-C").arg(&tmp).status()
    }?;
    anyhow::ensure!(ok.success(), "ekstrak ZAP gagal");
    let root = std::fs::read_dir(&tmp)?.flatten().map(|e| e.path()).find(|p| p.is_dir()).context("isi arsip ZAP kosong")?;
    std::fs::write(root.join(".appsec-version"), v)?;
    replace_dir(&root, &dir.join("zap"))?;
    let _ = std::fs::remove_dir_all(&tmp);
    msg.push(format!("ZAP {v} terpasang"));
    Ok(msg.join(" · "))
}

/// Pasang/update nmap lewat package manager OS (lisensi melarang dibundel, memasang dari repo resmi OS boleh).
/// Linux: pkexec <pm> → prompt kata sandi admin lewat polkit. macOS: brew (tanpa sudo).
fn install_nmap(log: &dyn Fn(&str)) -> Result<String> {
    if std::env::consts::OS == "macos" {
        let brew = which(Path::new("brew")).context("Homebrew tidak ditemukan; pasang brew dulu atau nmap dari nmap.org")?;
        let sub = if which(Path::new("nmap")).is_some() { "upgrade" } else { "install" };
        run_logged("brew", &brew, &[sub, "nmap"], log)?;
    } else {
        let pkexec = which(Path::new("pkexec")).context("pkexec (polkit) tidak ada; pasang nmap manual: `sudo apt install nmap` atau installer nmap.org")?;
        let args: Vec<&str> = if which(Path::new("apt-get")).is_some() {
            vec!["sh", "-c", "apt-get update && apt-get install -y nmap"]
        } else if which(Path::new("dnf")).is_some() {
            vec!["dnf", "install", "-y", "nmap"]
        } else if which(Path::new("pacman")).is_some() {
            vec!["pacman", "-S", "--noconfirm", "nmap"]
        } else if which(Path::new("zypper")).is_some() {
            vec!["zypper", "install", "-y", "nmap"]
        } else {
            bail!("Package manager tidak dikenal; pasang nmap dari paket distro Anda atau nmap.org");
        };
        log("Memasang nmap via package manager sistem (butuh izin admin lewat polkit)…");
        run_logged("nmap", &pkexec, &args, log)?;
    }
    let v = info("nmap").version.context("nmap terpasang tapi versinya tidak terbaca")?;
    Ok(format!("Selesai. nmap versi {v}"))
}

fn install_testssl(log: &dyn Fn(&str)) -> Result<String> {
    let dir = TOOLS_DIR.get().context("folder tools belum diset")?;
    anyhow::ensure!(cfg!(unix), "testssl.sh butuh bash: hanya Linux/macOS");
    if info("testssl").version.as_deref() == Some(TESTSSL_VERSION) && testssl().is_some_and(|p| p.starts_with(dir)) {
        return Ok(format!("Sudah versi {TESTSSL_VERSION}"));
    }
    let url = format!("https://github.com/testssl/testssl.sh/archive/refs/tags/v{TESTSSL_VERSION}.tar.gz");
    let (tmp, archive) = download_verified(dir, "testssl", &url, TESTSSL_SHA256, 300, log)?;
    anyhow::ensure!(Command::new("tar").arg("-xzf").arg(&archive).arg("-C").arg(&tmp).status()?.success(), "ekstrak testssl gagal");
    replace_dir(&tmp.join(format!("testssl.sh-{TESTSSL_VERSION}")), &dir.join("testssl"))?;
    let _ = std::fs::remove_dir_all(&tmp);
    Ok(format!("Terpasang versi {TESTSSL_VERSION}"))
}

/// Unduh rilis GitHub terbaru, verifikasi SHA-256 (digest aset dari API GitHub), pasang ke folder tools (atomic rename).
fn update_binary(name: &str, log: &dyn Fn(&str)) -> Result<String> {
    let dir = TOOLS_DIR.get().context("folder tools belum diset")?;
    let arm = std::env::consts::ARCH == "aarch64";
    let mac = std::env::consts::OS == "macos";
    anyhow::ensure!((mac || std::env::consts::OS == "linux") && (arm || std::env::consts::ARCH == "x86_64"), "Update otomatis hanya untuk Linux/macOS (x86_64/arm64)");
    let asset = match (name, mac) {
        ("gitleaks", false) => if arm { "gitleaks_{v}_linux_arm64.tar.gz" } else { "gitleaks_{v}_linux_x64.tar.gz" },
        ("gitleaks", true) => if arm { "gitleaks_{v}_darwin_arm64.tar.gz" } else { "gitleaks_{v}_darwin_x64.tar.gz" },
        ("trivy", false) => if arm { "trivy_{v}_Linux-ARM64.tar.gz" } else { "trivy_{v}_Linux-64bit.tar.gz" },
        ("trivy", true) => if arm { "trivy_{v}_macOS-ARM64.tar.gz" } else { "trivy_{v}_macOS-64bit.tar.gz" },
        ("katana", false) => if arm { "katana_{v}_linux_arm64.zip" } else { "katana_{v}_linux_amd64.zip" },
        ("katana", true) => if arm { "katana_{v}_macOS_arm64.zip" } else { "katana_{v}_macOS_amd64.zip" },
        ("ffuf", false) => if arm { "ffuf_{v}_linux_arm64.tar.gz" } else { "ffuf_{v}_linux_amd64.tar.gz" },
        ("ffuf", true) => if arm { "ffuf_{v}_macOS_arm64.tar.gz" } else { "ffuf_{v}_macOS_amd64.tar.gz" },
        ("dalfox", false) => if arm { "dalfox-{tag}-linux-aarch64.tar.gz" } else { "dalfox-{tag}-linux-x86_64.tar.gz" },
        ("dalfox", true) => if arm { "dalfox-{tag}-macos-aarch64.tar.gz" } else { "dalfox-{tag}-macos-x86_64.tar.gz" },
        (_, false) => if arm { "nuclei_{v}_linux_arm64.zip" } else { "nuclei_{v}_linux_amd64.zip" },
        (_, true) => if arm { "nuclei_{v}_macOS_arm64.zip" } else { "nuclei_{v}_macOS_amd64.zip" },
    };
    let http = http(30)?;
    log("cek rilis terbaru di GitHub…");
    let rel = json(&http, &format!("https://api.github.com/repos/{}/releases/latest", repo(name)))?;
    let tag = rel["tag_name"].as_str().context("tag rilis tidak ditemukan")?;
    let v = tag.trim_start_matches('v');
    if info(name).version.as_deref() == Some(v) {
        return Ok(format!("Sudah versi terbaru ({v})"));
    }
    let asset = asset.replace("{v}", v).replace("{tag}", tag);
    let a = rel["assets"].as_array().into_iter().flatten().find(|a| a["name"] == asset.as_str()).with_context(|| format!("aset {asset} tidak ada di rilis {tag}"))?;
    let sum = a["digest"].as_str().and_then(|d| d.strip_prefix("sha256:")).context("checksum aset tidak tersedia")?;
    let (tmp, archive) = download_verified(dir, name, a["browser_download_url"].as_str().unwrap_or_default(), sum, 600, log)?;
    let ok = if asset.ends_with(".zip") {
        Command::new("unzip").args(["-o", "-q"]).arg(&archive).arg("-d").arg(&tmp).status()
    } else {
        Command::new("tar").arg("-xzf").arg(&archive).arg("-C").arg(&tmp).status()
    }.with_context(|| format!("{} tidak tersedia", if asset.ends_with(".zip") { "unzip" } else { "tar" }))?;
    anyhow::ensure!(ok.success(), "ekstrak {asset} gagal");
    let new = find_file(&tmp, name).with_context(|| format!("{name} tidak ada di arsip"))?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&new, std::fs::Permissions::from_mode(0o755))?;
    // rename atomic: scan yang sedang jalan tetap memakai binary lama.
    std::fs::rename(&new, dir.join(name))?;
    let _ = std::fs::remove_dir_all(&tmp);
    Ok(format!("Terpasang versi {v}"))
}

/// Cari file bernama `name` di folder (rekursif; arsip kadang menaruh binary di subfolder).
fn find_file(dir: &Path, name: &str) -> Option<PathBuf> {
    for e in std::fs::read_dir(dir).ok()?.flatten() {
        let p = e.path();
        if p.is_dir() {
            if let Some(f) = find_file(&p, name) {
                return Some(f);
            }
        } else if p.file_name().is_some_and(|n| n == name) {
            return Some(p);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_versions_and_old_settings() {
        assert_eq!(after("Version: 0.76.1\nVulnerability DB:\n  UpdatedAt: 2026-11-05 01:19", "Version:").as_deref(), Some("0.76.1"));
        assert_eq!(after("[INF] Nuclei Engine Version: v3.11.1", "Engine Version:").as_deref(), Some("3.11.1"));
        assert_eq!(after("x UpdatedAt: 2026-11-05 01:19", "UpdatedAt:").as_deref(), Some("2026-11-05"));
        // Setting lama / sebagian tetap terbaca dengan default.
        let o: ToolOptions = serde_json::from_str(r#"{"nuclei_rate": 10}"#).unwrap();
        assert_eq!((o.nuclei_rate, o.gitleaks_history), (10, true));
    }
}
