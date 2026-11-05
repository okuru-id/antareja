use crate::domain::{FindingStatus, Scan, ScanMode, ScanRepository, Scanner, TargetKind, TargetRepository};
use anyhow::{Result, bail};
use chrono::Utc;
use std::collections::HashMap;
use std::path::Path;
use uuid::Uuid;

/// Scanner bawaan sesuai jenis target.
pub fn scanners_for(kind: &TargetKind, opts: crate::dast::DastOptions, tools: &crate::tools::ToolOptions) -> Vec<Box<dyn Scanner>> {
    match kind {
        TargetKind::Url(_) => crate::dast::default_scanners(opts, tools),
        TargetKind::SourcePath(_) => crate::sast::default_scanners(tools),
    }
}

/// Tautkan target folder (SAST) dengan URL (DAST) aplikasi yang sama; `None` melepas tautan.
pub fn link_targets(repo: &impl TargetRepository, a: Uuid, b: Option<Uuid>) -> Result<()> {
    let Some(ta) = repo.get(a)? else { bail!("Target tidak terdaftar") };
    if let Some(b) = b {
        let Some(tb) = repo.get(b)? else { bail!("Target pasangan tidak terdaftar") };
        if std::mem::discriminant(&ta.kind) == std::mem::discriminant(&tb.kind) {
            bail!("Tautan harus antara folder project (SAST) dan URL (DAST)");
        }
    }
    repo.link(a, b)
}

/// Jalankan semua scanner paralel pada target terdaftar (guardrail: hanya target milik sendiri).
/// Kegagalan satu scanner dicatat di `errors`, hasil scanner lain tetap disimpan.
pub fn run_scan(
    repo: &(impl TargetRepository + ScanRepository),
    target_id: Uuid,
    scanners: &[Box<dyn Scanner>],
    progress: &(dyn Fn(&str) + Sync),
) -> Result<Scan> {
    run_scan_cancellable(repo, target_id, scanners, progress, &Default::default())
}

/// Seperti `run_scan`, tapi bisa dihentikan lewat `cancel`: tool eksternal dimatikan dan hasil tidak disimpan.
pub fn run_scan_cancellable(
    repo: &(impl TargetRepository + ScanRepository),
    target_id: Uuid,
    scanners: &[Box<dyn Scanner>],
    progress: &(dyn Fn(&str) + Sync),
    cancel: &crate::cancel::Token,
) -> Result<Scan> {
    let Some(target) = repo.get(target_id)? else { bail!("Target tidak terdaftar") };
    if !target.owned {
        bail!("Target belum dikonfirmasi milik sendiri");
    }
    let mode = match &target.kind {
        TargetKind::Url(_) => ScanMode::Dast,
        TargetKind::SourcePath(p) if Path::new(p).is_dir() => ScanMode::Sast,
        TargetKind::SourcePath(p) => bail!("Folder tidak ditemukan: {p}"),
    };
    let target_value = target.kind.value();

    let started_at = Utc::now();
    let results: Vec<_> = std::thread::scope(|s| {
        let handles: Vec<_> = scanners
            .iter()
            .map(|sc| s.spawn(move || {
                crate::cancel::set(Some(cancel.clone()));
                progress(&format!("{} berjalan…", sc.name()));
                let t = std::time::Instant::now();
                let r = sc.scan(target_value, &|m: &str| progress(&format!("  {}: {m}", sc.name())));
                let secs = t.elapsed().as_secs_f32();
                match &r {
                    Ok(f) => progress(&format!("{} selesai: {} temuan ({secs:.1} dtk)", sc.name(), f.len())),
                    Err(e) => progress(&format!("{} gagal ({secs:.1} dtk): {e:#}", sc.name())),
                }
                (sc.name().to_string(), r)
            }))
            .collect();
        handles.into_iter().map(|h| h.join().expect("scanner panic")).collect()
    });

    if crate::cancel::is_cancelled(cancel) {
        bail!("Scan dihentikan; hasil tidak disimpan");
    }
    let (mut findings, mut errors) = (vec![], vec![]);
    for (name, r) in results {
        match r {
            Ok(f) => findings.extend(f),
            Err(e) => errors.push(format!("{name}: {e:#}")),
        }
    }
    findings.sort_by_key(|f| f.severity);

    // Keputusan manual (Accepted Risk / False Positive) ikut ke scan berikutnya.
    // "Fixed" sengaja tidak: kalau temuan muncul lagi berarti belum beres -> Open.
    let decided: HashMap<_, _> = repo
        .latest(target_id)?
        .map(|prev| prev.findings)
        .unwrap_or_default()
        .into_iter()
        .filter(|f| matches!(f.status, FindingStatus::AcceptedRisk | FindingStatus::FalsePositive))
        .map(|f| (f.key(), f.status))
        .collect();
    for f in &mut findings {
        if let Some(&st) = decided.get(&f.key()) {
            f.status = st;
        }
    }

    let scan = Scan {
        id: Uuid::new_v4(),
        target_id,
        mode,
        started_at,
        finished_at: Some(Utc::now()),
        findings,
        errors,
    };
    repo.save(&scan)?;
    Ok(scan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{Finding, Severity, Target};
    use crate::sqlite::Db;

    struct Fake(&'static str, Option<Severity>);
    impl Scanner for Fake {
        fn name(&self) -> &str { self.0 }
        fn scan(&self, _: &str, _: &dyn Fn(&str)) -> Result<Vec<Finding>> {
            let Some(severity) = self.1 else { bail!("boom") };
            Ok(vec![Finding {
                id: Uuid::new_v4(), mode: ScanMode::Sast, tool: self.0.into(), severity,
                title: "t".into(), location: "a.php:1".into(), description: String::new(),
                impact: String::new(), recommendation: String::new(), status: FindingStatus::Open, rule_id: None, evidence: String::new(), confirmed: None,
            }])
        }
    }

    #[test]
    fn partial_failure_keeps_other_results() {
        let db = Db::open_in_memory().unwrap();
        let t = Target::new(TargetKind::SourcePath(".".into()), "", true).unwrap();
        db.add(&t).unwrap();
        let scanners: Vec<Box<dyn Scanner>> =
            vec![Box::new(Fake("A", Some(Severity::Low))), Box::new(Fake("B", None)), Box::new(Fake("C", Some(Severity::Critical)))];

        let scan = run_scan(&db, t.id, &scanners, &|_| {}).unwrap();
        assert_eq!(scan.mode, ScanMode::Sast);
        assert_eq!(scan.errors, vec!["B: boom"]);
        assert_eq!(scan.findings.iter().map(|f| f.severity).collect::<Vec<_>>(), [Severity::Critical, Severity::Low]);
        assert_eq!(db.latest(t.id).unwrap().unwrap(), scan);

        // status manual terbawa ke scan berikutnya, kecuali Fixed
        db.set_status(scan.findings[0].id, FindingStatus::FalsePositive).unwrap();
        db.set_status(scan.findings[1].id, FindingStatus::Fixed).unwrap();
        let next = run_scan(&db, t.id, &scanners, &|_| {}).unwrap();
        assert_eq!(next.findings.iter().map(|f| f.status).collect::<Vec<_>>(), [FindingStatus::FalsePositive, FindingStatus::Open]);
        assert!(db.set_status(Uuid::new_v4(), FindingStatus::Fixed).is_err());

        let url = Target::new(TargetKind::Url("example.com".into()), "", true).unwrap();
        db.add(&url).unwrap();
        assert_eq!(run_scan(&db, url.id, &scanners, &|_| {}).unwrap().mode, ScanMode::Dast);
        assert!(run_scan(&db, Uuid::new_v4(), &scanners, &|_| {}).is_err());

        // tautan: hanya folder <-> URL, dua arah, lepas saat target dihapus
        let url2 = Target::new(TargetKind::Url("example.org".into()), "", true).unwrap();
        db.add(&url2).unwrap();
        assert!(link_targets(&db, url.id, Some(url2.id)).is_err());
        link_targets(&db, t.id, Some(url.id)).unwrap();
        link_targets(&db, t.id, Some(url2.id)).unwrap(); // pindah pasangan
        assert_eq!(db.get(url2.id).unwrap().unwrap().linked, Some(t.id));
        assert_eq!(db.get(url.id).unwrap().unwrap().linked, None);

        db.remove(t.id).unwrap(); // cascade ke scans/findings
        assert_eq!(db.get(url2.id).unwrap().unwrap().linked, None);
        assert_eq!(db.latest(t.id).unwrap(), None);
    }
}
