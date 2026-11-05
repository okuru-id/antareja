//! Modul intrusif (mengirim payload serangan / fuzzing): sqlmap, dalfox, ffuf, ZAP active scan.
//! Hanya boleh ke host lokal (localhost, 127.0.0.0/8, ::1, *.localhost, *.test) atau domain dev yang
//! didaftarkan pengguna di Pengaturan. Dicek ulang di setiap modul sebelum mengirim request.
use crate::domain::{Finding, ScanMode, Scanner, Severity};
use anyhow::{Context, Result, bail};
use serde_json::Value;
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use url::Url;

/// Nama modul intrusif (sama dengan `Scanner::name`).
pub const MODULES: &[&str] = &["sqlmap", "dalfox", "ffuf", "ZAP-active"];

/// Host boleh diserang? `extra`: domain dev dari Pengaturan ("dev.app.com" persis, "*.dev.app.com" semua subdomain).
pub fn host_allowed(host: &str, extra: &[String]) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']').to_ascii_lowercase();
    if let Ok(ip) = host.parse::<IpAddr>() {
        return ip.is_loopback();
    }
    host == "localhost" || host.ends_with(".localhost") || host.ends_with(".test")
        || extra.iter().map(|d| d.trim().to_ascii_lowercase()).filter(|d| !d.is_empty()).any(|d| match d.strip_prefix("*.") {
            Some(base) => host.ends_with(&format!(".{base}")),
            None => host == d,
        })
}

pub fn check(target: &str, extra: &[String]) -> Result<()> {
    let url = Url::parse(target).context("URL target tidak valid")?;
    let host = url.host_str().context("host kosong")?;
    if !host_allowed(host, extra) {
        bail!("Modul intrusif hanya untuk localhost atau domain dev yang diizinkan di Pengaturan; {host} tidak termasuk");
    }
    Ok(())
}

pub fn scanners(names: &[String], extra: &[String], rate: u32) -> Vec<Box<dyn Scanner>> {
    let rate = rate.clamp(1, 500).to_string();
    let mut v: Vec<Box<dyn Scanner>> = vec![];
    for n in names {
        let allow = extra.to_vec();
        match n.as_str() {
            "sqlmap" => v.push(Box::new(Sqlmap { allow })),
            "dalfox" => v.push(Box::new(Dalfox { allow, rate: rate.clone() })),
            "ffuf" => v.push(Box::new(Ffuf { allow, rate: rate.clone() })),
            "ZAP-active" => v.push(Box::new(ZapActive { allow })),
            _ => {}
        }
    }
    v
}

fn finding(tool: &str, severity: Severity, rule_id: &str) -> Finding {
    Finding::new(ScanMode::Dast, tool, severity, rule_id)
}

/// Folder kerja unik per scan (dibuat baru, dihapus setelahnya).
fn work() -> Result<PathBuf> {
    // nosemgrep: rust.lang.security.temp-dir.temp-dir
    let d = std::env::temp_dir().join(format!("appsec-intrusive-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&d)?;
    Ok(d)
}

fn with_work<T>(f: impl FnOnce(&Path) -> Result<T>) -> Result<T> {
    let d = work()?;
    let r = f(&d);
    let _ = std::fs::remove_dir_all(&d);
    r
}

// ---------------- sqlmap ----------------

pub struct Sqlmap {
    allow: Vec<String>,
}

impl Scanner for Sqlmap {
    fn name(&self) -> &str { "sqlmap" }
    fn scan(&self, target: &str, log: &dyn Fn(&str)) -> Result<Vec<Finding>> {
        check(target, &self.allow)?;
        with_work(|dir| {
            let csv = dir.join("hasil.csv");
            let (csv_s, out_s) = (csv.to_string_lossy().to_string(), dir.join("out").to_string_lossy().to_string());
            // Level/risk terendah, crawl 2 tingkat + form; --batch = jawaban default tanpa interaksi.
            crate::sast::run_path("sqlmap", &crate::tools::bin("sqlmap"), dir, &[
                "-u", target, "--crawl=2", "--forms", "--batch", "--level", "1", "--risk", "1", "--smart",
                "--threads", "2", "--disable-coloring", "--results-file", &csv_s, "--output-dir", &out_s,
            ], log)?;
            Ok(parse_sqlmap(&std::fs::read_to_string(&csv).unwrap_or_default()))
        })
    }
}

pub fn parse_sqlmap(csv: &str) -> Vec<Finding> {
    let tech = |c: char| match c {
        'B' => "boolean-based blind", 'E' => "error-based", 'U' => "UNION query", 'S' => "stacked queries",
        'T' => "time-based blind", 'Q' => "inline query", _ => "lainnya",
    };
    csv.lines().skip(1).filter_map(|l| {
        let f: Vec<&str> = l.split(',').collect();
        let (url, place, param, techs) = (*f.first()?, *f.get(1)?, *f.get(2)?, *f.get(3)?);
        if param.is_empty() {
            return None;
        }
        let names = techs.chars().map(tech).collect::<Vec<_>>().join(", ");
        Some(Finding {
            title: format!("SQL injection pada parameter {param}"),
            location: url.into(),
            description: format!("sqlmap berhasil menyuntikkan SQL lewat parameter {param} ({place}). Teknik: {names}."),
            impact: "Penyerang bisa membaca, mengubah, atau menghapus isi database, dan kadang menjalankan perintah di server.".into(),
            recommendation: "Pakai parameterized query / prepared statement atau ORM untuk semua input; jangan menyusun SQL dengan menggabung string. Batasi hak akun database aplikasi.".into(),
            evidence: format!("url: {url}\nlokasi: {place}\nparameter: {param}\nteknik: {techs} ({names})\nreproduksi: sqlmap -u '{url}' -p {param} --batch"),
            ..finding("sqlmap", Severity::Critical, &format!("sqli-{param}"))
        })
    }).collect()
}

// ---------------- dalfox (XSS) ----------------

pub struct Dalfox {
    allow: Vec<String>,
    rate: String,
}

impl Scanner for Dalfox {
    fn name(&self) -> &str { "dalfox" }
    fn scan(&self, target: &str, log: &dyn Fn(&str)) -> Result<Vec<Finding>> {
        check(target, &self.allow)?;
        with_work(|dir| {
            // URL berparameter dari crawl Katana (bila terpasang) + target itu sendiri.
            let mut urls = vec![target.to_string()];
            if crate::tools::installed("katana") {
                log("crawl Katana untuk mencari parameter…");
                let out = crate::sast::run("katana", dir, &["-u", target, "-d", "2", "-ct", "60s", "-fs", "fqdn", "-jc", "-silent", "-nc", "-duc", "-rl", &self.rate], log)?;
                urls.extend(String::from_utf8_lossy(&out).lines().filter(|l| l.contains('?')).map(String::from));
            }
            urls.dedup();
            let list = dir.join("urls.txt");
            std::fs::File::create(&list)?.write_all(urls.join("\n").as_bytes())?;
            let json = dir.join("dalfox.json");
            // dalfox keluar dengan kode 1 bila menemukan XSS: yang menentukan adalah laporan JSON-nya.
            let r = crate::sast::run("dalfox", dir, &[
                "scan", "-i", "file", list.to_str().unwrap_or_default(), "-S", "--no-color", "-f", "json",
                "-o", json.to_str().unwrap_or_default(), "--rate-limit", &self.rate,
            ], log);
            let data = match (std::fs::read(&json), r) {
                (Ok(d), _) => d,
                (Err(_), Err(e)) => return Err(e),
                (Err(_), Ok(_)) => b"{}".to_vec(),
            };
            Ok(parse_dalfox(&serde_json::from_slice(&data)?))
        })
    }
}

pub fn parse_dalfox(v: &Value) -> Vec<Finding> {
    let mut seen = std::collections::HashSet::new();
    v["findings"].as_array().into_iter().flatten().filter_map(|x| {
        let g = |k: &str| x[k].as_str().unwrap_or_default();
        // V = terbukti tereksekusi, R = payload terpantul (perlu dicek manual).
        let sev = match g("type") { "V" => Severity::High, "R" => Severity::Medium, _ => return None };
        let url = g("data");
        let base = url.split('?').next().unwrap_or(url).to_string();
        if !seen.insert((base.clone(), g("param").to_string(), g("type").to_string())) {
            return None;
        }
        Some(Finding {
            title: format!("{} XSS pada parameter {}", if g("type") == "V" { "Reflected" } else { "Kemungkinan" }, g("param")),
            location: base,
            description: format!("{} ({})", g("message_str"), g("type_description")),
            impact: "Penyerang bisa menjalankan JavaScript di browser korban: mencuri sesi, mengubah tampilan, atau bertindak atas nama pengguna.".into(),
            recommendation: "Escape output sesuai konteks (HTML, atribut, JS, URL) lewat fitur template engine, validasi input, dan pasang Content-Security-Policy yang ketat.".into(),
            evidence: format!("param: {} ({})\npayload: {}\nPoC: {url}\ndeteksi: {} · {}", g("param"), g("location"), g("payload"), g("detection_method"), g("evidence")),
            ..finding("dalfox", sev, &format!("xss-{}", g("param")))
        })
    }).collect()
}

// ---------------- ffuf (content discovery) ----------------

pub struct Ffuf {
    allow: Vec<String>,
    rate: String,
}

/// Wordlist ringkas path umum yang sering bocor/terlupa (bukan brute-force besar).
const WORDLIST: &[&str] = &[
    "admin", "administrator", "admin.php", "login", "dashboard", "panel", "cpanel", "manage", "manager", "console",
    "api", "api/v1", "api/v2", "graphql", "swagger", "swagger-ui", "swagger.json", "openapi.json", "api-docs", "docs",
    "debug", "test", "tests", "dev", "staging", "beta", "old", "new", "tmp", "temp",
    "backup", "backups", "backup.zip", "backup.tar.gz", "backup.sql", "db.sql", "dump.sql", "database.sql", "site.zip", "www.zip",
    ".env", ".env.local", ".env.production", ".git", ".git/config", ".svn", ".hg", ".DS_Store", ".htaccess", ".htpasswd",
    "config", "config.php", "config.json", "config.yml", "settings.py", "web.config", "app.config", "configuration.php", "wp-config.php.bak", "config.php.bak",
    "phpinfo.php", "info.php", "server-status", "server-info", "status", "health", "metrics", "actuator", "actuator/env", "actuator/heapdump",
    "uploads", "upload", "files", "file", "static", "assets", "media", "images", "download", "downloads",
    "logs", "log", "error.log", "access.log", "debug.log", "storage", "storage/logs/laravel.log", "vendor", "node_modules", "package.json",
    "composer.json", "composer.lock", "yarn.lock", "Dockerfile", "docker-compose.yml", "README.md", "CHANGELOG.md", "robots.txt", "sitemap.xml", "crossdomain.xml",
    "phpmyadmin", "pma", "adminer.php", "wp-admin", "wp-login.php", "xmlrpc.php", "user", "users", "account", "register",
    "private", "secret", "internal", "hidden", "export", "import", "cgi-bin", "shell", "cmd", "jenkins",
];

const SENSITIVE: &[&str] = &[".env", ".git", ".svn", ".hg", ".htpasswd", "backup", ".sql", ".zip", ".tar.gz", ".bak", "config", "phpinfo", "info.php",
    "server-status", "server-info", "actuator", "heapdump", "log", "phpmyadmin", "adminer", "admin", "console", "debug", "secret", "private", "dump", "shell"];

impl Scanner for Ffuf {
    fn name(&self) -> &str { "ffuf" }
    fn scan(&self, target: &str, log: &dyn Fn(&str)) -> Result<Vec<Finding>> {
        check(target, &self.allow)?;
        with_work(|dir| {
            let list = dir.join("wordlist.txt");
            std::fs::File::create(&list)?.write_all(WORDLIST.join("\n").as_bytes())?;
            let out = dir.join("ffuf.json");
            let url = format!("{}/FUZZ", target.trim_end_matches('/'));
            // -ac: kalibrasi otomatis membuang respons "halaman tidak ditemukan" yang berstatus 200.
            crate::sast::run("ffuf", dir, &[
                "-u", &url, "-w", list.to_str().unwrap_or_default(), "-ac", "-mc", "200,204,301,302,307,401,403,500",
                "-rate", &self.rate, "-t", "10", "-maxtime", "300", "-noninteractive", "-s",
                "-of", "json", "-o", out.to_str().unwrap_or_default(),
            ], log)?;
            let v: Value = serde_json::from_slice(&std::fs::read(&out).unwrap_or_else(|_| b"{}".to_vec()))?;
            Ok(parse_ffuf(&v, target))
        })
    }
}

pub fn parse_ffuf(v: &Value, target: &str) -> Vec<Finding> {
    let hits: Vec<(String, u64, u64)> = v["results"].as_array().into_iter().flatten().map(|r| (
        r["input"]["FUZZ"].as_str().unwrap_or_default().to_string(), r["status"].as_u64().unwrap_or(0), r["length"].as_u64().unwrap_or(0),
    )).collect();
    let mut out: Vec<Finding> = hits.iter().filter(|(p, st, _)| *st == 200 && SENSITIVE.iter().any(|k| p.to_ascii_lowercase().contains(k))).map(|(p, st, len)| {
        let url = format!("{}/{p}", target.trim_end_matches('/'));
        Finding {
            title: format!("Path sensitif dapat diakses: /{p}"),
            location: url.clone(),
            description: format!("ffuf menemukan /{p} menjawab HTTP {st} ({len} byte) tanpa login."),
            impact: "File/halaman seperti ini sering berisi kredensial, backup data, konfigurasi, atau panel admin.".into(),
            recommendation: format!("Hapus /{p} dari server publik atau lindungi dengan autentikasi; pastikan file backup/konfigurasi tidak ikut ter-deploy."),
            evidence: format!("GET {url} → {st} ({len} byte)"),
            ..finding("ffuf", Severity::Medium, &format!("ffuf-{p}"))
        }
    }).collect();
    if !hits.is_empty() {
        out.push(Finding {
            title: format!("{} path ditemukan ffuf", hits.len()),
            location: target.into(),
            description: "Path dari wordlist ringkas yang menjawab (selain halaman 404 standar).".into(),
            impact: "Peta konten tersembunyi; tinjau yang tidak seharusnya publik.".into(),
            recommendation: "Tinjau daftar ini dan tutup path yang tidak perlu publik.".into(),
            evidence: hits.iter().map(|(p, st, len)| format!("/{p}  {st}  {len} byte")).collect::<Vec<_>>().join("\n"),
            ..finding("ffuf", Severity::Info, "ffuf-paths")
        });
    }
    out
}

// ---------------- ZAP active scan ----------------

pub struct ZapActive {
    allow: Vec<String>,
}

impl Scanner for ZapActive {
    fn name(&self) -> &str { "ZAP-active" }
    fn scan(&self, target: &str, log: &dyn Fn(&str)) -> Result<Vec<Finding>> {
        check(target, &self.allow)?;
        crate::dast::Zap { active: true }.scan(target, log)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_local_or_allowed_hosts() {
        let extra = vec!["dev.app.com".to_string(), "*.staging.app.com".to_string()];
        for h in ["localhost", "127.0.0.1", "127.8.0.1", "::1", "[::1]", "api.localhost", "shop.test", "dev.app.com", "a.staging.app.com"] {
            assert!(host_allowed(h, &extra), "{h} harus diizinkan");
        }
        for h in ["example.com", "app.com", "evil-dev.app.com", "staging.app.com", "10.0.0.5", "192.168.1.10", "localhost.evil.com", "test"] {
            assert!(!host_allowed(h, &extra), "{h} harus ditolak");
        }
        assert!(check("https://example.com", &extra).is_err());
    }

    #[test]
    fn parse_tool_outputs() {
        let sq = parse_sqlmap("Target URL,Place,Parameter,Technique(s),Note(s)\nhttp://127.0.0.1:8765/item?id=1,GET,id,BETU,\n");
        assert_eq!((sq.len(), sq[0].severity, sq[0].location.as_str()), (1, Severity::Critical, "http://127.0.0.1:8765/item?id=1"));
        let ff = parse_ffuf(&serde_json::json!({"results": [{"input": {"FUZZ": ".env"}, "status": 200, "length": 20}, {"input": {"FUZZ": "docs"}, "status": 301, "length": 0}]}), "http://x.test/");
        assert_eq!(ff.iter().map(|f| f.severity).collect::<Vec<_>>(), vec![Severity::Medium, Severity::Info]);
    }
}
