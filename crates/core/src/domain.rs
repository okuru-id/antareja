use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum TargetKind {
    Url(String),
    SourcePath(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Target {
    pub id: Uuid,
    pub kind: TargetKind,
    pub label: String,
    pub owned: bool,
    pub created_at: DateTime<Utc>,
    /// Target pasangan (folder <-> URL aplikasi yang sama) untuk korelasi DAST/SAST.
    #[serde(default)]
    pub linked: Option<Uuid>,
}

impl Target {
    /// Validasi input user (trust boundary) + guardrail kepemilikan.
    pub fn new(kind: TargetKind, label: &str, owned: bool) -> Result<Self> {
        if !owned {
            bail!("Target harus dikonfirmasi milik sendiri / terotorisasi");
        }
        let kind = match kind {
            TargetKind::Url(raw) => TargetKind::Url(normalize_url(&raw)?),
            TargetKind::SourcePath(raw) => {
                let p = Path::new(raw.trim());
                if !p.is_dir() {
                    bail!("Folder tidak ditemukan: {raw}");
                }
                TargetKind::SourcePath(p.canonicalize()?.to_string_lossy().into_owned())
            }
        };
        let label = label.trim();
        Ok(Self {
            id: Uuid::new_v4(),
            label: if label.is_empty() { kind.value().to_string() } else { label.to_string() },
            kind,
            owned,
            created_at: Utc::now(),
            linked: None,
        })
    }
}

impl TargetKind {
    pub fn value(&self) -> &str {
        match self {
            Self::Url(v) | Self::SourcePath(v) => v,
        }
    }
}

fn normalize_url(raw: &str) -> Result<String> {
    let raw = raw.trim();
    let with_scheme = if raw.contains("://") { raw.to_string() } else { format!("https://{raw}") };
    let url = url::Url::parse(&with_scheme)?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        bail!("URL harus http/https dengan host: {raw}");
    }
    Ok(url.origin().ascii_serialization())
}

// ponytail: sync karena rusqlite sync; jadikan async kalau ada backend async.
pub trait TargetRepository {
    fn add(&self, target: &Target) -> Result<()>;
    fn list(&self) -> Result<Vec<Target>>;
    fn get(&self, id: Uuid) -> Result<Option<Target>>;
    fn remove(&self, id: Uuid) -> Result<()>;
    /// Tautkan dua target secara dua arah (`None` = lepas tautan `a`).
    fn link(&self, a: Uuid, b: Option<Uuid>) -> Result<()>;
}

// ---- Temuan & scan ----

/// Urutan deklarasi = urutan tampil (Critical dulu).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity { Critical, High, Medium, Low, Info }

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum ScanMode { Dast, Sast }

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum FindingStatus { Open, Fixed, AcceptedRisk, FalsePositive }

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub id: Uuid,
    pub mode: ScanMode,
    pub tool: String,
    pub severity: Severity,
    pub title: String,
    /// URL atau "path/file.php:42" (relatif ke root project)
    pub location: String,
    pub description: String,
    pub impact: String,
    pub recommendation: String,
    pub status: FindingStatus,
    pub rule_id: Option<String>,
    /// Bukti mentah dari tes: potongan respons/header, banner port, baris kode, output tool.
    #[serde(default)]
    pub evidence: String,
    /// Diisi saat dibaca bila dikuatkan temuan mode lain (tidak disimpan).
    #[serde(default)]
    pub confirmed: Option<String>,
}

impl Finding {
    /// Identitas temuan lintas scan (id selalu baru tiap scan).
    // ponytail: lokasi file:baris ikut kunci; status hilang kalau kode di atasnya bergeser.
    pub fn key(&self) -> (String, Option<String>, String) {
        (self.tool.clone(), self.rule_id.clone(), self.location.clone())
    }

    /// Kerangka temuan; isi teks lewat struct update (`Finding { title, ..Finding::new(..) }`).
    pub fn new(mode: ScanMode, tool: &str, severity: Severity, rule_id: &str) -> Self {
        Self {
            id: Uuid::new_v4(),
            mode,
            tool: tool.into(),
            severity,
            title: String::new(),
            location: String::new(),
            description: String::new(),
            impact: String::new(),
            recommendation: String::new(),
            status: FindingStatus::Open,
            rule_id: Some(rule_id.into()),
            evidence: String::new(),
            confirmed: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Scan {
    pub id: Uuid,
    pub target_id: Uuid,
    pub mode: ScanMode,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub findings: Vec<Finding>,
    /// Error per modul; scan tetap tersimpan dengan hasil parsial.
    pub errors: Vec<String>,
}

pub trait ScanRepository {
    fn save(&self, scan: &Scan) -> Result<()>;
    // ponytail: hanya scan terakhir; tambah history() saat butuh perbandingan antar scan.
    fn latest(&self, target_id: Uuid) -> Result<Option<Scan>>;
    fn set_status(&self, finding_id: Uuid, status: FindingStatus) -> Result<()>;
}

/// `target` = path folder (SAST) atau URL origin (DAST).
pub trait Scanner: Sync {
    fn name(&self) -> &str;
    /// `log`: sub-log live (progres tool eksternal, port/file yang ketemu).
    fn scan(&self, target: &str, log: &dyn Fn(&str)) -> Result<Vec<Finding>>;
}
