//! Mode headless untuk CI. Exit code: 0 lolos, 1 ada temuan >= ambang, 2 error / modul scan gagal.
use anyhow::{Context, Result, bail};
use appsec_core::domain::{Scan, Severity, Target, TargetKind, TargetRepository};
use appsec_core::{dast::DastOptions, report, sqlite::Db, usecase};
use std::process::ExitCode;

const USAGE: &str = "\
Pakai: appsec scan <folder|url> [opsi]

  --format text|json|md   output ke stdout (default: text)
  --fail-on LEVEL         critical|high|medium|low|info|none (default: critical)
  --authorized            wajib untuk URL: menyatakan target milik sendiri / ada izin tertulis
  --nuclei                URL: tambah template nuclei (lambat, beberapa menit)
  --online                URL: second opinion Mozilla Observatory (hostname dikirim ke pihak ketiga)

Exit code: 0 lolos, 1 ada temuan >= --fail-on, 2 error atau ada modul scan yang gagal.";

struct Args {
    target: String,
    format: String,
    fail_on: Option<Severity>,
    authorized: bool,
    dast: DastOptions,
}

fn parse(mut it: impl Iterator<Item = String>) -> Result<Args> {
    if it.next().as_deref() != Some("scan") {
        bail!("perintah tidak dikenal");
    }
    let mut a = Args { target: String::new(), format: "text".into(), fail_on: Some(Severity::Critical), authorized: false, dast: DastOptions::default() };
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--format" => a.format = it.next().context("--format butuh nilai")?,
            "--fail-on" => {
                a.fail_on = match it.next().context("--fail-on butuh nilai")?.to_lowercase().as_str() {
                    "critical" => Some(Severity::Critical),
                    "high" => Some(Severity::High),
                    "medium" => Some(Severity::Medium),
                    "low" => Some(Severity::Low),
                    "info" => Some(Severity::Info),
                    "none" => None,
                    v => bail!("level --fail-on tidak dikenal: {v}"),
                }
            }
            "--authorized" => a.authorized = true,
            "--nuclei" => a.dast.nuclei = true,
            "--online" => a.dast.online = true,
            "-h" | "--help" => bail!("bantuan"),
            _ if a.target.is_empty() && !arg.starts_with("--") => a.target = arg,
            _ => bail!("argumen tidak dikenal: {arg}"),
        }
    }
    if a.target.is_empty() {
        bail!("target belum diisi");
    }
    if !["text", "json", "md"].contains(&a.format.as_str()) {
        bail!("format tidak dikenal: {}", a.format);
    }
    Ok(a)
}

fn run(a: &Args) -> Result<(Scan, Target)> {
    let kind = if std::path::Path::new(&a.target).is_dir() {
        TargetKind::SourcePath(a.target.clone())
    } else {
        // Guardrail sama dengan GUI: DAST hanya untuk target yang dinyatakan milik sendiri.
        if !a.authorized {
            bail!("target URL butuh --authorized (pastikan milik sendiri / ada izin tertulis)");
        }
        TargetKind::Url(a.target.clone())
    };
    let target = Target::new(kind, "", true)?;
    let db = Db::open_in_memory()?;
    db.add(&target)?;
    let scan = usecase::run_scan(&db, target.id, &usecase::scanners_for(&target.kind, a.dast, &Default::default()), &|m| eprintln!("· {m}"))?;
    Ok((scan, target))
}

fn main() -> ExitCode {
    // Argumen hanya opsi CLI, bukan untuk keputusan keamanan.
    // nosemgrep: rust.lang.security.args.args
    let a = match parse(std::env::args().skip(1)) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let (scan, target) = match run(&a) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e:#}");
            return ExitCode::from(2);
        }
    };

    match a.format.as_str() {
        "json" => println!("{}", serde_json::to_string_pretty(&scan).expect("serialize")),
        "md" => print!("{}", report::markdown(&[(target, scan.clone())], chrono::Utc::now())),
        _ => {
            for f in &scan.findings {
                println!("{:<8} {:<9} {}  {}", format!("{:?}", f.severity), f.tool, f.location, f.title);
            }
        }
    }

    let count = |s| scan.findings.iter().filter(|f| f.severity == s).count();
    eprintln!(
        "\nRingkasan: {} temuan (Critical {}, High {}, Medium {}, Low {}, Info {})",
        scan.findings.len(), count(Severity::Critical), count(Severity::High), count(Severity::Medium), count(Severity::Low), count(Severity::Info)
    );
    for e in &scan.errors {
        eprintln!("GAGAL  {e}");
    }
    if !scan.errors.is_empty() {
        eprintln!("Ada modul scan yang gagal: hasil tidak lengkap.");
        return ExitCode::from(2);
    }
    // Severity terurut Critical < High < ...: "di atas ambang" = nilai enum <= ambang.
    if let Some(t) = a.fail_on {
        let bad = scan.findings.iter().filter(|f| f.severity <= t).count();
        if bad > 0 {
            eprintln!("GAGAL: {bad} temuan dengan severity {t:?} atau lebih tinggi.");
            return ExitCode::from(1);
        }
    }
    eprintln!("LOLOS");
    ExitCode::SUCCESS
}
