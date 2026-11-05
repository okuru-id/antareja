use crate::domain::{Finding, FindingStatus, Scan, ScanRepository, Target, TargetKind, TargetRepository};
use anyhow::Result;
use rusqlite::{Connection, Row, params};
use serde::{Serialize, de::DeserializeOwned};
use std::{path::Path, sync::Mutex};
use uuid::Uuid;

#[derive(Debug, Serialize)]
pub struct ScanSummary {
    pub id: Uuid,
    pub target_id: Uuid,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub finished_at: Option<chrono::DateTime<chrono::Utc>>,
    pub errors: usize,
    /// Temuan Open per severity: [Critical, High, Medium, Low, Info].
    pub open: [u32; 5],
}

// ponytail: satu koneksi di balik Mutex; cukup untuk app desktop single-user.
pub struct Db(Mutex<Connection>);

impl Db {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let conn = Connection::open(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // DB bisa berisi temuan sensitif: hanya owner yang boleh baca.
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Self::init(conn)
    }

    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS targets (
                id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                value TEXT NOT NULL,
                label TEXT NOT NULL,
                owned INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(kind, value)
            );
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
                mode TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                errors TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                mode TEXT NOT NULL,
                tool TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                location TEXT NOT NULL,
                description TEXT NOT NULL,
                impact TEXT NOT NULL,
                recommendation TEXT NOT NULL,
                status TEXT NOT NULL,
                rule_id TEXT,
                evidence TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS scans_target ON scans(target_id, started_at);
            CREATE INDEX IF NOT EXISTS findings_scan ON findings(scan_id);
            CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            PRAGMA foreign_keys = ON;",
        )?;
        // Migrasi DB lama (sebelum fitur tautan target / evidence).
        for alter in ["ALTER TABLE targets ADD COLUMN linked TEXT", "ALTER TABLE findings ADD COLUMN evidence TEXT NOT NULL DEFAULT ''"] {
            if let Err(e) = conn.execute(alter, []) {
                anyhow::ensure!(e.to_string().contains("duplicate column"), e);
            }
        }
        Ok(Self(Mutex::new(conn)))
    }
}

impl Db {
    /// Setting aplikasi sebagai JSON per key; default kalau belum pernah disimpan.
    pub fn setting<T: DeserializeOwned + Default>(&self, key: &str) -> Result<T> {
        let conn = self.0.lock().unwrap();
        let v: Option<String> = conn
            .query_row("SELECT value FROM settings WHERE key = ?1", [key], |r| r.get(0))
            .map(Some)
            .or_else(|e| if e == rusqlite::Error::QueryReturnedNoRows { Ok(None) } else { Err(e) })?;
        Ok(v.and_then(|v| serde_json::from_str(&v).ok()).unwrap_or_default())
    }

    /// Ringkasan semua scan (lama -> baru): jumlah temuan Open per severity, untuk tren & riwayat.
    pub fn history(&self) -> Result<Vec<ScanSummary>> {
        let conn = self.0.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT s.id, s.target_id, s.started_at, s.finished_at, s.errors,
                COUNT(CASE WHEN f.status = 'Open' AND f.severity = 'Critical' THEN 1 END),
                COUNT(CASE WHEN f.status = 'Open' AND f.severity = 'High' THEN 1 END),
                COUNT(CASE WHEN f.status = 'Open' AND f.severity = 'Medium' THEN 1 END),
                COUNT(CASE WHEN f.status = 'Open' AND f.severity = 'Low' THEN 1 END),
                COUNT(CASE WHEN f.status = 'Open' AND f.severity = 'Info' THEN 1 END)
             FROM scans s LEFT JOIN findings f ON f.scan_id = s.id
             GROUP BY s.id ORDER BY s.started_at",
        )?;
        let rows = stmt.query_map([], |r| Ok(ScanSummary {
            id: r.get(0)?,
            target_id: r.get(1)?,
            started_at: r.get(2)?,
            finished_at: r.get(3)?,
            errors: serde_json::from_str::<Vec<String>>(&r.get::<_, String>(4)?).map(|e| e.len()).unwrap_or(0),
            open: [r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?, r.get(9)?],
        }))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn set_setting<T: Serialize>(&self, key: &str, value: &T) -> Result<()> {
        self.0.lock().unwrap().execute(
            "INSERT INTO settings VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, serde_json::to_string(value)?],
        )?;
        Ok(())
    }
}

/// Enum <-> teks lewat serde ("Critical", "Sast", ...).
fn enc<T: Serialize>(v: &T) -> String {
    serde_json::to_value(v).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default()
}
fn dec<T: DeserializeOwned>(s: String) -> rusqlite::Result<T> {
    serde_json::from_value(serde_json::Value::String(s))
        .map_err(|e| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, e.into()))
}

impl ScanRepository for Db {
    fn save(&self, s: &Scan) -> Result<()> {
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO scans VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![s.id, s.target_id, enc(&s.mode), s.started_at, s.finished_at, serde_json::to_string(&s.errors)?],
        )?;
        for f in &s.findings {
            tx.execute(
                "INSERT INTO findings VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![f.id, s.id, enc(&f.mode), f.tool, enc(&f.severity), f.title, f.location,
                    f.description, f.impact, f.recommendation, enc(&f.status), f.rule_id, f.evidence],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    fn latest(&self, target_id: Uuid) -> Result<Option<Scan>> {
        let conn = self.0.lock().unwrap();
        let scan = conn.query_row(
            "SELECT id, target_id, mode, started_at, finished_at, errors FROM scans
             WHERE target_id = ?1 ORDER BY started_at DESC LIMIT 1",
            [target_id],
            |r| Ok(Scan {
                id: r.get(0)?,
                target_id: r.get(1)?,
                mode: dec(r.get(2)?)?,
                started_at: r.get(3)?,
                finished_at: r.get(4)?,
                errors: serde_json::from_str(&r.get::<_, String>(5)?).unwrap_or_default(),
                findings: vec![],
            }),
        );
        let mut scan = match scan {
            Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
            s => s?,
        };
        let mut stmt = conn.prepare(
            "SELECT id, mode, tool, severity, title, location, description, impact, recommendation, status, rule_id, evidence
             FROM findings WHERE scan_id = ?1",
        )?;
        scan.findings = stmt
            .query_map([scan.id], |r| Ok(Finding {
                id: r.get(0)?,
                mode: dec(r.get(1)?)?,
                tool: r.get(2)?,
                severity: dec(r.get(3)?)?,
                title: r.get(4)?,
                location: r.get(5)?,
                description: r.get(6)?,
                impact: r.get(7)?,
                recommendation: r.get(8)?,
                status: dec(r.get(9)?)?,
                rule_id: r.get(10)?,
                evidence: r.get(11)?,
                confirmed: None,
            }))?
            .collect::<rusqlite::Result<_>>()?;
        scan.findings.sort_by_key(|f| f.severity);
        Ok(Some(scan))
    }

    fn set_status(&self, finding_id: Uuid, status: FindingStatus) -> Result<()> {
        let n = self.0.lock().unwrap().execute("UPDATE findings SET status = ?1 WHERE id = ?2", params![enc(&status), finding_id])?;
        anyhow::ensure!(n == 1, "Temuan tidak ditemukan");
        Ok(())
    }
}

fn row_to_target(r: &Row) -> rusqlite::Result<Target> {
    let kind: String = r.get(1)?;
    let value: String = r.get(2)?;
    Ok(Target {
        id: r.get(0)?,
        kind: if kind == "url" { TargetKind::Url(value) } else { TargetKind::SourcePath(value) },
        label: r.get(3)?,
        owned: r.get(4)?,
        created_at: r.get(5)?,
        linked: r.get(6)?,
    })
}

const SELECT: &str = "SELECT id, kind, value, label, owned, created_at, linked FROM targets";

impl TargetRepository for Db {
    fn add(&self, t: &Target) -> Result<()> {
        let kind = match t.kind {
            TargetKind::Url(_) => "url",
            TargetKind::SourcePath(_) => "path",
        };
        self.0.lock().unwrap().execute(
            "INSERT INTO targets (id, kind, value, label, owned, created_at, linked) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![t.id, kind, t.kind.value(), t.label, t.owned, t.created_at, t.linked],
        ).map_err(|e| match e {
            rusqlite::Error::SqliteFailure(f, _) if f.code == rusqlite::ErrorCode::ConstraintViolation => {
                anyhow::anyhow!("Target sudah terdaftar: {}", t.kind.value())
            }
            e => e.into(),
        })?;
        Ok(())
    }

    fn list(&self) -> Result<Vec<Target>> {
        let conn = self.0.lock().unwrap();
        let mut stmt = conn.prepare(&format!("{SELECT} ORDER BY created_at"))?;
        Ok(stmt.query_map([], row_to_target)?.collect::<rusqlite::Result<_>>()?)
    }

    fn get(&self, id: Uuid) -> Result<Option<Target>> {
        let conn = self.0.lock().unwrap();
        let mut stmt = conn.prepare(&format!("{SELECT} WHERE id = ?1"))?;
        Ok(stmt.query_map([id], row_to_target)?.next().transpose()?)
    }

    fn remove(&self, id: Uuid) -> Result<()> {
        let conn = self.0.lock().unwrap();
        conn.execute("UPDATE targets SET linked = NULL WHERE linked = ?1", [id])?;
        conn.execute("DELETE FROM targets WHERE id = ?1", [id])?;
        Ok(())
    }

    fn link(&self, a: Uuid, b: Option<Uuid>) -> Result<()> {
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        // Satu target hanya punya satu pasangan: lepas tautan lama kedua sisi dulu.
        for id in std::iter::once(a).chain(b) {
            tx.execute("UPDATE targets SET linked = NULL WHERE id = ?1 OR linked = ?1", [id])?;
        }
        if let Some(b) = b {
            tx.execute("UPDATE targets SET linked = ?2 WHERE id = ?1", params![a, b])?;
            tx.execute("UPDATE targets SET linked = ?2 WHERE id = ?1", params![b, a])?;
        }
        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_crud_and_guardrails() {
        let db = Db::open_in_memory().unwrap();
        assert!(Target::new(TargetKind::Url("example.com".into()), "", false).is_err());
        assert!(Target::new(TargetKind::Url("ftp://x".into()), "", true).is_err());
        assert!(Target::new(TargetKind::SourcePath("/nope/xyz".into()), "", true).is_err());

        let t = Target::new(TargetKind::Url("Example.com/login?a=1".into()), "web", true).unwrap();
        assert_eq!(t.kind, TargetKind::Url("https://example.com".into()));
        db.add(&t).unwrap();
        assert!(db.add(&Target::new(TargetKind::Url("https://example.com".into()), "", true).unwrap()).is_err());

        let p = Target::new(TargetKind::SourcePath(".".into()), "", true).unwrap();
        db.add(&p).unwrap();
        assert_eq!(db.list().unwrap(), vec![t.clone(), p]);
        assert_eq!(db.get(t.id).unwrap(), Some(t.clone()));
        db.remove(t.id).unwrap();
        assert_eq!(db.get(t.id).unwrap(), None);

        let o: crate::dast::DastOptions = db.setting("dast").unwrap();
        assert_eq!(o, Default::default());
        let on = crate::dast::DastOptions { nuclei: true, ..Default::default() };
        db.set_setting("dast", &on).unwrap();
        db.set_setting("dast", &on).unwrap(); // upsert
        assert_eq!(db.setting::<crate::dast::DastOptions>("dast").unwrap(), on);
    }

    #[test]
    fn history_counts_open_per_severity() {
        use crate::domain::{ScanMode, Severity};
        let db = Db::open_in_memory().unwrap();
        let t = Target::new(TargetKind::Url("example.com".into()), "", true).unwrap();
        db.add(&t).unwrap();
        let f = |sev, status| Finding { status, ..Finding::new(ScanMode::Dast, "x", sev, "r") };
        let scan = |findings| Scan { id: Uuid::new_v4(), target_id: t.id, mode: ScanMode::Dast, started_at: chrono::Utc::now(),
            finished_at: None, findings, errors: vec!["e".into()] };
        db.save(&scan(vec![])).unwrap();
        db.save(&scan(vec![f(Severity::Critical, FindingStatus::Open), f(Severity::Critical, FindingStatus::FalsePositive),
            f(Severity::Low, FindingStatus::Open)])).unwrap();
        let h = db.history().unwrap();
        assert_eq!(h.len(), 2);
        assert_eq!((h[0].open, h[0].errors), ([0; 5], 1));
        assert_eq!(h[1].open, [1, 0, 0, 1, 0]);
    }
}
