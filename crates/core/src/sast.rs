//! Adapter SAST: jalankan Semgrep / Gitleaks / Trivy, normalisasi output JSON ke `Finding`.
use crate::domain::{Finding, ScanMode, Scanner, Severity};
use crate::tools::ToolOptions;
use anyhow::{Context, Result, bail};
use serde_json::Value;
use std::path::Path;
use std::io::{BufRead, BufReader, Read};
use std::process::{Command, Stdio};

pub fn default_scanners(o: &ToolOptions) -> Vec<Box<dyn Scanner>> {
    vec![
        Box::new(Semgrep { extra: o.semgrep_extra.clone(), exclude: o.semgrep_exclude.clone() }),
        Box::new(Gitleaks { history: o.gitleaks_history }),
        Box::new(Trivy { ignore_unfixed: o.trivy_ignore_unfixed, misconfig: o.trivy_misconfig, license: o.trivy_license }),
    ]
}

/// Jalankan tool; stdout = hasil, stderr diteruskan baris per baris ke `log` (sub-log live).
pub(crate) fn run(name: &str, root: &Path, args: &[&str], log: &dyn Fn(&str)) -> Result<Vec<u8>> {
    run_path(name, &crate::tools::bin(name), root, args, log)
}

pub(crate) fn run_path(name: &str, cmd: &Path, root: &Path, args: &[&str], log: &dyn Fn(&str)) -> Result<Vec<u8>> {
    let mut c = Command::new(cmd);
    c.args(args).current_dir(root).stdout(Stdio::piped()).stderr(Stdio::piped());
    // Grup proses sendiri agar "Hentikan" ikut mematikan anak proses tool (mis. semgrep-core).
    #[cfg(unix)]
    std::os::unix::process::CommandExt::process_group(&mut c, 0);
    let mut child = c.spawn().with_context(|| format!("{name} tidak ditemukan; pastikan terpasang / ada di PATH"))?;
    let mut stdout = child.stdout.take().expect("piped");
    let stderr = child.stderr.take().expect("piped");
    let pid = child.id();
    let finished = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    if let Some(token) = crate::cancel::current() {
        let finished = finished.clone();
        std::thread::spawn(move || {
            while !finished.load(std::sync::atomic::Ordering::Relaxed) {
                if crate::cancel::is_cancelled(&token) {
                    // Bunuh seluruh pohon proses lewat pid (thread utama sedang membaca output).
                    #[cfg(unix)]
                    let _ = Command::new("kill").args(["-KILL", &format!("-{pid}")]).status();
                    #[cfg(windows)]
                    let _ = Command::new("taskkill").args(["/F", "/T", "/PID", &pid.to_string()]).status();
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
        });
    }
    let reader = std::thread::spawn(move || {
        let mut v = vec![];
        stdout.read_to_end(&mut v).map(|_| v)
    });
    let mut tail = std::collections::VecDeque::new();
    // Progress bar memakai \r: anggap juga sebagai pemisah baris.
    for chunk in BufReader::new(stderr).split(b'\n') {
        for line in chunk?.split(|&b| b == b'\r') {
            let line = strip_ansi(&String::from_utf8_lossy(line));
            // Buang timestamp "2026-..T..\t" (Trivy) dan dekorasi kotak (Semgrep).
            let line = line.split_once('\t').filter(|(t, _)| t.starts_with("20")).map_or(line.as_str(), |(_, r)| r).trim();
            if line.is_empty() || line.starts_with(['┌', '│', '└', '─']) {
                continue;
            }
            log(&line.chars().take(300).collect::<String>());
            tail.push_back(line.to_string());
            if tail.len() > 5 {
                tail.pop_front();
            }
        }
    }
    // Tandai selesai sebelum wait(): setelah di-reap, pid bisa dipakai proses lain.
    finished.store(true, std::sync::atomic::Ordering::Relaxed);
    let status = child.wait()?;
    let out = reader.join().expect("reader panic")?;
    if crate::cancel::current().is_some_and(|t| crate::cancel::is_cancelled(&t)) {
        bail!("{name} dihentikan");
    }
    if !status.success() {
        bail!("{name} gagal ({status}): {}", Vec::from(tail).join(" | "));
    }
    Ok(out)
}

pub(crate) fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c == '\x1b' {
            // CSI: ESC [ ... huruf
            for d in it.by_ref() {
                if d.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn finding(tool: &str, severity: Severity, rule_id: &str) -> Finding {
    Finding::new(ScanMode::Sast, tool, severity, rule_id)
}

fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key].as_str().unwrap_or_default()
}

fn rel(root: &Path, file: &str) -> String {
    Path::new(file).strip_prefix(root).map(|p| p.to_string_lossy().into_owned()).unwrap_or_else(|_| file.into())
}

// ---------------- Semgrep ----------------

pub struct Semgrep {
    pub extra: Vec<String>,
    pub exclude: Vec<String>,
}

/// Rule pack per stack, dideteksi dari file penanda di root project.
// ponytail: hanya cek root; monorepo dengan stack di subfolder tetap kena p/default.
pub fn semgrep_configs(root: &Path) -> Vec<&'static str> {
    let has = |f: &str| root.join(f).exists();
    let mut c = vec!["p/default", "p/security-audit"];
    let packs: &[(&[&str], &[&str])] = &[
        (&["composer.json"], &["p/php"]),
        (&["package.json"], &["p/javascript", "p/typescript"]),
        (&["requirements.txt", "pyproject.toml", "setup.py"], &["p/python"]),
        (&["go.mod"], &["p/golang"]),
        (&["pom.xml", "build.gradle", "build.gradle.kts"], &["p/java"]),
        (&["Gemfile"], &["p/ruby"]),
        (&["Cargo.toml"], &["p/rust"]),
    ];
    for (markers, cfg) in packs {
        if markers.iter().any(|m| has(m)) {
            c.extend_from_slice(cfg);
        }
    }
    c
}

impl Scanner for Semgrep {
    fn name(&self) -> &str { "Semgrep" }
    fn scan(&self, root: &str, log: &dyn Fn(&str)) -> Result<Vec<Finding>> {
        let root = Path::new(root);
        let mut args = vec!["scan", "--json", "--metrics=off", "--disable-version-check"];
        for c in semgrep_configs(root).into_iter().chain(self.extra.iter().map(String::as_str)) {
            args.extend(["--config", c]);
        }
        for x in &self.exclude {
            args.extend(["--exclude", x]);
        }
        args.push(".");
        parse_semgrep(&serde_json::from_slice(&run("semgrep", root, &args, log)?)?, root)
    }
}

pub fn parse_semgrep(v: &Value, root: &Path) -> Result<Vec<Finding>> {
    let results = v["results"].as_array().context("output semgrep tanpa 'results'")?;
    // Secret jadi urusan Gitleaks (riwayat git + redaksi); hindari temuan ganda.
    Ok(results.iter().filter(|r| !s(r, "check_id").contains(".secrets.")).map(|r| {
        let x = &r["extra"];
        let m = &x["metadata"];
        let id = s(r, "check_id");
        let mut f = finding("Semgrep", match s(x, "severity") {
            "CRITICAL" => Severity::Critical,
            "ERROR" | "HIGH" => Severity::High,
            "WARNING" | "MEDIUM" => Severity::Medium,
            "INFO" | "LOW" => Severity::Low,
            _ => Severity::Info,
        }, id);
        let name = id.rsplit('.').next().unwrap_or(id).replace('-', " ");
        let mut c = name.chars();
        f.title = c.next().map(|h| h.to_uppercase().chain(c).collect()).unwrap_or_default();
        f.location = format!("{}:{}", s(r, "path"), r["start"]["line"]);
        f.description = s(x, "message").into();
        f.evidence = code_lines(root, s(r, "path"), &r["start"]["line"], &r["end"]["line"])
            .unwrap_or_else(|| s(x, "lines").into());
        let list = |k: &str| m[k].as_array().map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>()).unwrap_or_default();
        f.impact = [list("cwe"), list("owasp")].concat().join("\n");
        f.recommendation = match x["fix"].as_str() {
            Some(fix) => format!("Contoh perbaikan:\n{fix}"),
            None => format!("Referensi:\n{}", list("references").iter().take(3).copied().collect::<Vec<_>>().join("\n")),
        };
        f
    }).collect())
}

/// Baris kode yang ditandai (maks 10) + 2 baris konteks, dengan nomor baris; `>` = baris temuan.
/// Dibaca dari file karena Semgrep tanpa login mengisi `extra.lines` dengan "requires login".
fn code_lines(root: &Path, path: &str, start: &Value, end: &Value) -> Option<String> {
    let (a, b) = (start.as_u64()? as usize, end.as_u64()? as usize);
    let text = std::fs::read_to_string(root.join(path)).ok()?;
    let b = b.min(a + 9);
    let from = a.saturating_sub(2).max(1);
    Some(text.lines().enumerate().skip(from - 1).take(b + 2 - from + 1)
        .map(|(i, l)| format!("{} {:>4} | {}", if (a..=b).contains(&(i + 1)) { '>' } else { ' ' }, i + 1, l.chars().take(200).collect::<String>()))
        .collect::<Vec<_>>().join("\n"))
}

// ---------------- Gitleaks ----------------

pub struct Gitleaks {
    pub history: bool,
}

impl Scanner for Gitleaks {
    fn name(&self) -> &str { "Gitleaks" }
    fn scan(&self, root: &str, log: &dyn Fn(&str)) -> Result<Vec<Finding>> {
        let root = Path::new(root);
        // Repo git: pindai seluruh riwayat commit (secret yang "sudah dihapus" tetap bocor).
        let mode = if self.history && root.join(".git").exists() { "git" } else { "dir" };
        let out = run("gitleaks", root, &[
            mode, ".", "--report-format", "json", "--report-path", "-",
            "--redact=85", "--no-banner", "--log-level", "info", "--exit-code", "0",
        ], log)?;
        let mut found = parse_gitleaks(&serde_json::from_slice(&out)?, root)?;
        // Mode dir tidak membaca .gitignore: buang hasil build/dependency (mis. target/*.rmeta) yang bukan kode project.
        if mode == "dir" {
            found.retain(|f| !f.location.split('/').any(|c| GENERATED_DIRS.contains(&c)));
        }
        Ok(found)
    }
}

const GENERATED_DIRS: [&str; 6] = ["target", "node_modules", "dist", ".venv", "__pycache__", ".git"];

pub fn parse_gitleaks(v: &Value, root: &Path) -> Result<Vec<Finding>> {
    let items = v.as_array().context("output gitleaks bukan array")?;
    Ok(items.iter().map(|r| {
        let rule = s(r, "RuleID");
        let mut f = finding("Gitleaks", Severity::Critical, rule);
        f.title = format!("Secret terdeteksi: {rule}");
        f.location = format!("{}:{}", rel(root, s(r, "File")), r["StartLine"]);
        let commit = s(r, "Commit");
        if !commit.is_empty() {
            f.location += &format!(" @{}", &commit[..commit.len().min(8)]);
        }
        f.description = s(r, "Description").into();
        // Match di-redact sebagian oleh Gitleaks (--redact=85: hanya awalan secret yang terlihat).
        f.evidence = [("match", "Match"), ("commit", "Commit"), ("author", "Author"), ("tanggal", "Date"), ("pesan commit", "Message")]
            .iter()
            .filter(|(_, k)| !s(r, k).is_empty())
            .map(|(l, k)| format!("{l}: {}", s(r, k).lines().next().unwrap_or_default()))
            .collect::<Vec<_>>()
            .join("\n");
        f.impact = "Siapa pun yang punya akses ke repository (atau riwayat git-nya) bisa memakai kredensial ini.".into();
        f.recommendation = "Cabut (revoke) dan rotasi kredensial ini sekarang, lalu pindahkan ke environment variable / secret manager. \
            Menghapus dari kode saja tidak cukup kalau sudah ter-commit.".into();
        f
    }).collect())
}

// ---------------- Trivy ----------------

pub struct Trivy {
    pub ignore_unfixed: bool,
    pub misconfig: bool,
    pub license: bool,
}

impl Scanner for Trivy {
    fn name(&self) -> &str { "Trivy" }
    fn scan(&self, root: &str, log: &dyn Fn(&str)) -> Result<Vec<Finding>> {
        let root = Path::new(root);
        let scanners = ["vuln"].into_iter()
            .chain(self.misconfig.then_some("misconfig"))
            .chain(self.license.then_some("license"))
            .collect::<Vec<_>>().join(",");
        let mut args = vec!["fs", "--scanners", &scanners, "--format", "json", "--no-progress"];
        if self.ignore_unfixed {
            args.push("--ignore-unfixed");
        }
        args.push(".");
        let out = run("trivy", root, &args, log)?;
        parse_trivy(&serde_json::from_slice(&out)?)
    }
}

pub fn parse_trivy(v: &Value) -> Result<Vec<Finding>> {
    let mut out = vec![];
    for res in v["Results"].as_array().into_iter().flatten() {
        for x in res["Vulnerabilities"].as_array().into_iter().flatten() {
            let (id, pkg, ver, fixed) = (s(x, "VulnerabilityID"), s(x, "PkgName"), s(x, "InstalledVersion"), s(x, "FixedVersion"));
            let mut f = finding("Trivy", trivy_sev(s(x, "Severity")), id);
            f.title = format!("{id} di {pkg} {ver}");
            f.location = s(res, "Target").into();
            f.description = format!("{}\n\n{}", s(x, "Title"), s(x, "Description")).trim().into();
            f.impact = format!("Dependency {pkg}@{ver} punya kerentanan publik yang diketahui ({id}).");
            f.evidence = format!("file: {}\npaket: {pkg}\nterpasang: {ver}\nversi perbaikan: {}\nsumber data: {}\nreferensi: {}",
                s(res, "Target"), if fixed.is_empty() { "-" } else { fixed },
                x["DataSource"]["Name"].as_str().unwrap_or("-"), s(x, "PrimaryURL"));
            f.recommendation = if fixed.is_empty() {
                format!("Belum ada versi perbaikan. Pertimbangkan ganti library atau mitigasi. Info: {}", s(x, "PrimaryURL"))
            } else {
                format!("Upgrade {pkg} ke versi {fixed} atau lebih baru.")
            };
            out.push(f);
        }
        // Salah konfigurasi IaC (hanya yang gagal).
        for x in res["Misconfigurations"].as_array().into_iter().flatten().filter(|x| s(x, "Status") == "FAIL") {
            let id = s(x, "ID");
            let mut f = finding("Trivy", trivy_sev(s(x, "Severity")), id);
            f.title = format!("{} ({id})", s(x, "Title"));
            let line = x["CauseMetadata"]["StartLine"].as_u64();
            f.location = match line { Some(l) if l > 0 => format!("{}:{l}", s(res, "Target")), _ => s(res, "Target").into() };
            f.description = s(x, "Description").into();
            f.impact = format!("Konfigurasi {} tidak mengikuti praktik aman: {}", x["CauseMetadata"]["Provider"].as_str().unwrap_or("infrastruktur"), s(x, "Message"));
            f.recommendation = format!("{} Info: {}", s(x, "Resolution"), s(x, "PrimaryURL")).trim().into();
            f.evidence = format!("file: {}\npesan: {}", s(res, "Target"), s(x, "Message"));
            out.push(f);
        }
        // Lisensi: hanya kategori yang membatasi pemakaian (copyleft kuat / dilarang); sisanya bukan risiko.
        for x in res["Licenses"].as_array().into_iter().flatten() {
            let sev = match s(x, "Category") { "forbidden" => Severity::Medium, "restricted" => Severity::Low, _ => continue };
            let (name, pkg) = (s(x, "Name"), s(x, "PkgName"));
            let mut f = finding("Trivy", sev, &format!("license/{pkg}/{name}"));
            f.title = format!("Lisensi {name} pada {}", if pkg.is_empty() { "file" } else { pkg });
            f.location = [s(x, "FilePath"), s(res, "Target")].into_iter().find(|p| !p.is_empty()).unwrap_or_default().into();
            f.description = format!("Dependency memakai lisensi {name} (kategori {}).", s(x, "Category"));
            f.impact = "Lisensi copyleft/terlarang bisa mewajibkan membuka kode sumber aplikasi atau melanggar kebijakan perusahaan saat didistribusikan.".into();
            f.recommendation = "Pastikan pemakaian sesuai lisensi (cek dengan tim legal), atau ganti dengan library berlisensi permisif.".into();
            f.evidence = format!("paket: {}\nlisensi: {name}\nkategori: {}", if pkg.is_empty() { "-" } else { pkg }, s(x, "Category"));
            out.push(f);
        }
    }
    Ok(out)
}

fn trivy_sev(s: &str) -> Severity {
    match s {
        "CRITICAL" => Severity::Critical,
        "HIGH" => Severity::High,
        "MEDIUM" => Severity::Medium,
        "LOW" => Severity::Low,
        _ => Severity::Info,
    }
}

/// SBOM CycloneDX dari folder project (daftar komponen + lisensi), langsung ditulis ke `out`.
pub fn sbom(root: &Path, out: &Path, log: &dyn Fn(&str)) -> Result<()> {
    let out = out.to_str().context("path SBOM tidak valid")?;
    run("trivy", root, &["fs", "--format", "cyclonedx", "--output", out, "--no-progress", "."], log).map(|_| ())
}

/// SBOM CycloneDX (JSON) + kerentanan tertanam, untuk viewer dashboard SBOM dalam app.
pub fn sbom_json(root: &Path, log: &dyn Fn(&str)) -> Result<String> {
    let out = run("trivy", root, &["fs", "--format", "cyclonedx", "--scanners", "vuln", "--no-progress", "."], log)?;
    Ok(String::from_utf8(out)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[cfg(unix)]
    #[test]
    fn cancel_kills_tool_and_its_children() {
        let token = crate::cancel::Token::default();
        crate::cancel::set(Some(token.clone()));
        let t = token.clone();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(300));
            t.store(true, std::sync::atomic::Ordering::Relaxed);
        });
        let start = std::time::Instant::now();
        // Cucu proses mewarisi stderr: kalau tidak ikut mati, pembacaan stderr menggantung 30 dtk.
        let r = run_path("sh", Path::new("sh"), Path::new("."), &["-c", "sleep 30 & sleep 30"], &|_| {});
        crate::cancel::set(None);
        assert!(r.unwrap_err().to_string().contains("dihentikan"));
        assert!(start.elapsed() < std::time::Duration::from_secs(3));
    }

    #[test]
    fn parsers_normalize_tool_output() {
        let sg = parse_semgrep(&json!({"results": [{
            "check_id": "php.lang.security.injection.tainted-sql-string",
            "path": "src/user.php", "start": {"line": 3},
            "extra": {"severity": "ERROR", "message": "SQLi", "metadata": {"cwe": ["CWE-89"], "references": ["https://x"]}}
        }]}), Path::new("/p")).unwrap();
        assert_eq!((sg[0].severity, sg[0].title.as_str(), sg[0].location.as_str()), (Severity::High, "Tainted sql string", "src/user.php:3"));
        assert_eq!(sg[0].impact, "CWE-89");

        let gl = parse_gitleaks(&json!([{"RuleID": "aws-access-token", "File": "/p/src/config.js", "StartLine": 1, "Commit": "abcdef1234567"}]), Path::new("/p")).unwrap();
        assert_eq!(gl[0].location, "src/config.js:1 @abcdef12");
        assert_eq!(gl[0].severity, Severity::Critical);

        let tv = parse_trivy(&json!({"Results": [{"Target": "package-lock.json", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2020-8203", "PkgName": "lodash", "InstalledVersion": "4.17.15", "FixedVersion": "4.17.19", "Severity": "HIGH"}
        ]}, {"Target": "go.sum"}]})).unwrap();
        assert_eq!(tv.len(), 1);
        assert_eq!(tv[0].recommendation, "Upgrade lodash ke versi 4.17.19 atau lebih baru.");

        assert!(parse_semgrep(&json!({}), Path::new("/p")).is_err());
    }
}
