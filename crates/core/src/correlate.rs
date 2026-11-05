//! Korelasi DAST <-> SAST untuk target yang ditautkan (aplikasi yang sama).
//! DAST di sini non-intrusif, jadi hanya pasangan yang jelas saling menguatkan:
//! temuan kode + bukti yang sama terlihat dari luar.
use crate::domain::{Finding, FindingStatus, Scan, ScanMode, Severity, Target};

struct Rule {
    sast: fn(&Finding) -> bool,
    dast: fn(&Finding) -> bool,
    why: &'static str,
}

fn rule(f: &Finding) -> &str {
    f.rule_id.as_deref().unwrap_or_default()
}
fn file(f: &Finding) -> &str {
    let path = f.location.split([':', ' ']).next().unwrap_or_default();
    path.rsplit('/').next().unwrap_or(path)
}

const RULES: &[Rule] = &[
    Rule {
        sast: |f| f.tool == "Gitleaks" && file(f).starts_with(".env"),
        dast: |f| rule(f) == "/.env" || (f.tool == "Nuclei" && rule(f).contains("env")),
        why: "Terkonfirmasi: secret ada di file .env (Gitleaks) dan file .env bisa diunduh dari luar, jadi kredensial ini sudah terbuka ke publik.",
    },
    Rule {
        sast: |f| f.tool == "Gitleaks" && f.location.contains(" @"),
        dast: |f| rule(f) == "/.git/HEAD" || rule(f) == "git-config",
        why: "Terkonfirmasi: riwayat git berisi secret dan folder .git bisa diakses dari luar, jadi secret di commit lama ikut bisa diambil.",
    },
    Rule {
        sast: |f| f.tool == "Semgrep" && rule(f).contains("debug"),
        dast: |f| rule(f) == "/appsec-scanner-not-found-check" || rule(f) == "/_ignition/health-check",
        why: "Terkonfirmasi: mode debug aktif di kode dan halaman debug terlihat dari luar.",
    },
    Rule {
        sast: |f| f.tool == "Semgrep" && f.impact.contains("CWE-79"),
        dast: |f| rule(f) == "Content-Security-Policy",
        why: "Saling menguatkan: ada potensi XSS di kode dan aplikasi tidak memasang CSP yang bisa meredamnya.",
    },
];

fn bump(s: Severity) -> Severity {
    match s {
        Severity::Critical | Severity::High => Severity::Critical,
        Severity::Medium => Severity::High,
        Severity::Low => Severity::Medium,
        Severity::Info => Severity::Low,
    }
}

fn confirm(f: &mut Finding, why: &str) {
    if f.confirmed.is_some() {
        return; // satu kali naik walau cocok dengan beberapa rule
    }
    let old = f.severity;
    f.severity = bump(old);
    f.confirmed = Some(if f.severity == old { why.into() } else { format!("{why} Prioritas dinaikkan dari {old:?}.") });
}

pub fn correlate(sast: &mut Scan, dast: &mut Scan) {
    let live = |f: &Finding| f.status != FindingStatus::FalsePositive;
    for r in RULES {
        if !sast.findings.iter().any(|f| live(f) && (r.sast)(f)) || !dast.findings.iter().any(|f| live(f) && (r.dast)(f)) {
            continue;
        }
        sast.findings.iter_mut().filter(|f| live(f) && (r.sast)(f)).for_each(|f| confirm(f, r.why));
        dast.findings.iter_mut().filter(|f| live(f) && (r.dast)(f)).for_each(|f| confirm(f, r.why));
    }
    sast.findings.sort_by_key(|f| f.severity);
    dast.findings.sort_by_key(|f| f.severity);
}

/// Korelasikan setiap pasangan tertaut yang sama-sama punya scan.
pub fn correlate_all(entries: &mut [(Target, Scan)]) {
    for i in 0..entries.len() {
        let Some(other) = entries[i].0.linked else { continue };
        let Some(j) = entries.iter().position(|(t, _)| t.id == other) else { continue };
        if entries[i].1.mode != ScanMode::Sast || entries[j].1.mode != ScanMode::Dast {
            continue; // proses tiap pasangan sekali, dari sisi SAST
        }
        let (a, b) = if i < j {
            let (l, r) = entries.split_at_mut(j);
            (&mut l[i].1, &mut r[0].1)
        } else {
            let (l, r) = entries.split_at_mut(i);
            (&mut r[0].1, &mut l[j].1)
        };
        correlate(a, b);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::TargetKind;
    use chrono::Utc;
    use uuid::Uuid;

    fn scan(target: &Target, mode: ScanMode, findings: Vec<Finding>) -> Scan {
        Scan { id: Uuid::new_v4(), target_id: target.id, mode, started_at: Utc::now(), finished_at: None, findings, errors: vec![] }
    }

    #[test]
    fn linked_pairs_confirm_and_bump() {
        let mut src = Target::new(TargetKind::SourcePath(".".into()), "src", true).unwrap();
        let mut web = Target::new(TargetKind::Url("example.com".into()), "web", true).unwrap();
        src.linked = Some(web.id);
        web.linked = Some(src.id);

        let secret = Finding { location: "config/.env:3".into(), ..Finding::new(ScanMode::Sast, "Gitleaks", Severity::Critical, "aws") };
        let xss = Finding { impact: "CWE-79: XSS".into(), ..Finding::new(ScanMode::Sast, "Semgrep", Severity::Medium, "xss") };
        let fp = Finding { status: FindingStatus::FalsePositive, ..xss.clone() };
        let unrelated = Finding::new(ScanMode::Sast, "Trivy", Severity::Low, "CVE-1");
        let env = Finding::new(ScanMode::Dast, "Files", Severity::Critical, "/.env");
        let csp = Finding::new(ScanMode::Dast, "Headers", Severity::Medium, "Content-Security-Policy");

        let mut entries = vec![
            (web.clone(), scan(&web, ScanMode::Dast, vec![env, csp])),
            (src.clone(), scan(&src, ScanMode::Sast, vec![secret, xss, fp, unrelated])),
        ];
        correlate_all(&mut entries);
        let (d, s) = (&entries[0].1.findings, &entries[1].1.findings);

        let sev = |fs: &[Finding]| fs.iter().map(|f| (f.severity, f.confirmed.is_some())).collect::<Vec<_>>();
        assert_eq!(sev(s), [(Severity::Critical, true), (Severity::High, true), (Severity::Medium, false), (Severity::Low, false)]);
        assert_eq!(sev(d), [(Severity::Critical, true), (Severity::High, true)]);
        assert!(s[1].confirmed.as_deref().unwrap().ends_with("Prioritas dinaikkan dari Medium."));

        // tanpa tautan: tidak ada perubahan
        let mut lone = vec![(Target { linked: None, ..src.clone() }, scan(&src, ScanMode::Sast, vec![Finding::new(ScanMode::Sast, "Gitleaks", Severity::High, "x")]))];
        correlate_all(&mut lone);
        assert!(lone[0].1.findings[0].confirmed.is_none());
    }
}
