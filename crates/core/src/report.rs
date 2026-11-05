//! Laporan Markdown: ringkasan per severity + detail tiap temuan, per target.
use crate::domain::{Scan, Severity, Target, TargetKind};
use chrono::{DateTime, Local, Utc};
use std::fmt::Write;

const SEVERITIES: [Severity; 5] = [Severity::Critical, Severity::High, Severity::Medium, Severity::Low, Severity::Info];

fn local(t: DateTime<Utc>) -> String {
    t.with_timezone(&Local).format("%Y-%m-%d %H:%M").to_string()
}

/// Isi teks dari scanner bisa memuat `|` atau baris baru; aman untuk sel tabel.
fn cell(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

pub fn markdown(entries: &[(Target, Scan)], now: DateTime<Utc>) -> String {
    let mut md = String::new();
    let all = || entries.iter().flat_map(|(_, s)| &s.findings);
    let count = |sev| all().filter(|f| f.severity == sev).count();

    let _ = writeln!(md, "# Laporan Keamanan Aplikasi\n");
    let _ = writeln!(md, "Dibuat: {} · Target: {} · Total temuan: {}\n", local(now), entries.len(), all().count());
    let _ = writeln!(md, "## Ringkasan\n\n| Severity | Jumlah |\n| --- | ---: |");
    for sev in SEVERITIES {
        let _ = writeln!(md, "| {sev:?} | {} |", count(sev));
    }
    let _ = writeln!(md, "\n| Target | Jenis | Scan terakhir | Critical | High | Medium | Low | Info |\n| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |");
    for (t, s) in entries {
        let n = |sev| s.findings.iter().filter(|f| f.severity == sev).count();
        let _ = writeln!(md, "| {} | {} | {} | {} | {} | {} | {} | {} |", cell(&t.label), kind(&t.kind), local(s.started_at),
            n(Severity::Critical), n(Severity::High), n(Severity::Medium), n(Severity::Low), n(Severity::Info));
    }
    let _ = writeln!(md, "\n> **Batas cakupan.** Laporan ini hasil pemindaian otomatis Level 1–2 (konfigurasi, header, TLS, port, file sensitif, \
        bug kode, secret, dependency rentan). Logic flaw, auth bypass berbasis alur bisnis, dan IDOR tidak tercakup dan tetap butuh pentest manual. \
        Tidak ada temuan ≠ aplikasi pasti aman.\n");

    for (t, s) in entries {
        let _ = writeln!(md, "## {}\n", t.label);
        let _ = writeln!(md, "- **Jenis:** {}\n- **Lokasi:** `{}`\n- **Scan:** {} – {}", kind(&t.kind), t.kind.value(),
            local(s.started_at), s.finished_at.map(local).unwrap_or_else(|| "-".into()));
        if !s.errors.is_empty() {
            let _ = writeln!(md, "- **Modul gagal (hasil parsial):**");
            for e in &s.errors {
                let _ = writeln!(md, "  - {}", cell(e));
            }
        }
        let _ = writeln!(md);
        if s.findings.is_empty() {
            let _ = writeln!(md, "Tidak ada temuan.\n");
        }
        for (i, f) in s.findings.iter().enumerate() {
            let _ = writeln!(md, "### {}. [{:?}] {}\n", i + 1, f.severity, f.title);
            let _ = write!(md, "- **Lokasi:** `{}`\n- **Tool:** {}", f.location, f.tool);
            if let Some(r) = &f.rule_id {
                let _ = write!(md, " · **Rule:** `{r}`");
            }
            let _ = writeln!(md, "\n- **Status:** {:?}", f.status);
            if let Some(c) = &f.confirmed {
                let _ = writeln!(md, "- **Korelasi DAST↔SAST:** {c}");
            }
            let _ = writeln!(md);
            for (h, body) in [("Apa masalahnya", &f.description), ("Kenapa berbahaya", &f.impact), ("Cara memperbaiki", &f.recommendation)] {
                if !body.is_empty() {
                    // Baris baru tunggal -> hard break Markdown, supaya daftar CWE / referensi tidak menyatu.
                    let _ = writeln!(md, "**{h}**\n\n{}\n", body.replace('\n', "  \n"));
                }
            }
            if !f.evidence.is_empty() {
                // Pagar lebih panjang dari deret backtick di dalam bukti supaya blok tidak bocor.
                let mut fence = "```".to_string();
                while f.evidence.contains(&fence) {
                    fence.push('`');
                }
                let _ = writeln!(md, "**Bukti**\n\n{fence}text\n{}\n{fence}\n", f.evidence);
            }
        }
    }
    md
}

fn kind(k: &TargetKind) -> &'static str {
    match k {
        TargetKind::Url(_) => "DAST (URL)",
        TargetKind::SourcePath(_) => "SAST (source code)",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{Finding, ScanMode};
    use uuid::Uuid;

    #[test]
    fn summary_and_details() {
        let t = Target::new(TargetKind::Url("example.com".into()), "Portal | Web", true).unwrap();
        let f = Finding { title: "File .env bisa diunduh".into(), location: "https://example.com/.env".into(),
            recommendation: "Blokir dotfile".into(), evidence: "GET /.env → 200\n```x".into(), ..Finding::new(ScanMode::Dast, "Files", Severity::Critical, "/.env") };
        let s = Scan { id: Uuid::new_v4(), target_id: t.id, mode: ScanMode::Dast, started_at: Utc::now(), finished_at: None,
            findings: vec![f], errors: vec!["Ports: timeout".into()] };
        let md = markdown(&[(t, s)], Utc::now());
        assert!(md.contains("| Critical | 1 |\n| High | 0 |"));
        assert!(md.contains("| Portal \\| Web | DAST (URL) |"));
        assert!(md.contains("### 1. [Critical] File .env bisa diunduh"));
        assert!(md.contains("**Cara memperbaiki**\n\nBlokir dotfile"));
        assert!(!md.contains("**Kenapa berbahaya**")); // kosong -> dilewati
        assert!(md.contains("  - Ports: timeout"));
        assert!(md.contains("**Bukti**\n\n````text\nGET /.env → 200\n```x\n````"));
    }
}
