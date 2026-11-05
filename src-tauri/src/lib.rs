use appsec_core::domain::{FindingStatus, Scan, ScanRepository, Target, TargetKind, TargetRepository};
use appsec_core::{correlate, dast::DastOptions, report, sqlite::Db, tools::{self, ToolOptions}, usecase};
use std::path::PathBuf;
use serde::{Serialize, Deserialize};
use tauri::{AppHandle, Emitter, Manager, State};
use uuid::Uuid;

type Res<T> = Result<T, String>;
fn err(e: anyhow::Error) -> String {
    format!("{e:#}")
}

#[tauri::command]
fn list_targets(db: State<Db>) -> Res<Vec<Target>> {
    db.list().map_err(err)
}

#[tauri::command]
fn add_target(db: State<Db>, kind: TargetKind, label: String, owned: bool) -> Res<Target> {
    let t = Target::new(kind, &label, owned).map_err(err)?;
    db.add(&t).map_err(err)?;
    Ok(t)
}

#[tauri::command]
fn link_target(db: State<Db>, id: Uuid, other: Option<Uuid>) -> Res<()> {
    usecase::link_targets(&*db, id, other).map_err(err)
}

#[tauri::command]
fn remove_target(db: State<Db>, id: Uuid) -> Res<()> {
    db.remove(id).map_err(err)
}

#[derive(Clone, Serialize)]
struct Progress<'a> {
    /// id target, atau "update-<tool>" untuk log update tool.
    target_id: String,
    msg: &'a str,
}

/// SBOM CycloneDX (JSON) dari target folder, dibuat Trivy.
#[tauri::command]
async fn export_sbom(app: AppHandle, target_id: Uuid, path: PathBuf) -> Res<PathBuf> {
    tauri::async_runtime::spawn_blocking(move || {
        let target = app.state::<Db>().get(target_id).map_err(err)?.ok_or("Target tidak terdaftar")?;
        let TargetKind::SourcePath(root) = target.kind else { return Err("SBOM hanya untuk target folder (SAST)".into()) };
        appsec_core::sast::sbom(std::path::Path::new(&root), &path, &|_| {}).map_err(err)?;
        Ok(path)
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Token pembatalan scan yang sedang berjalan, per target.
#[derive(Default)]
struct Running(std::sync::Mutex<std::collections::HashMap<Uuid, appsec_core::cancel::Token>>);

/// Hentikan scan target: tool eksternal dimatikan, modul bawaan selesai sendiri (maks. hitungan detik), hasil dibuang.
#[tauri::command]
fn cancel_scan(running: State<Running>, target_id: Uuid) {
    if let Some(t) = running.0.lock().unwrap().get(&target_id) {
        t.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Scan bisa makan menit: jalan di thread blocking, progress dikirim lewat event "scan-progress" (per target).
/// `modules`: hanya jalankan modul bernama ini (None = semua sesuai Settings).
/// `deep`: mode Full — Nuclei aktif, riwayat git dipindai, rule pack OWASP Semgrep ditambahkan.
#[tauri::command]
async fn run_scan(app: AppHandle, target_id: Uuid, modules: Option<Vec<String>>, deep: Option<bool>) -> Res<Scan> {
    tauri::async_runtime::spawn_blocking(move || {
        let progress = |msg: &str| {
            let _ = app.emit("scan-progress", Progress { target_id: target_id.to_string(), msg });
        };
        let db = app.state::<Db>();
        let target = db.get(target_id).map_err(err)?.ok_or("Target tidak terdaftar")?;
        let (mut dast, mut topts): (DastOptions, ToolOptions) =
            (db.setting("dast").map_err(err)?, db.setting("tools").map_err(err)?);
        // Modul yang dipilih eksplisit ikut dijalankan walau mati di Pengaturan.
        if let Some(m) = &modules {
            let has = |n: &str| m.iter().any(|x| x == n);
            dast.nuclei |= has("Nuclei");
            dast.testssl |= has("testssl");
            dast.nmap |= has("Nmap");
            dast.zap |= has("ZAP");
        }
        if deep == Some(true) {
            dast.nuclei = true;
            topts.gitleaks_history = true;
            for p in ["p/owasp-top-ten", "p/security-audit"] {
                if !topts.semgrep_extra.iter().any(|x| x == p) { topts.semgrep_extra.push(p.into()) }
            }
        }
        let mut scanners = usecase::scanners_for(&target.kind, dast, &topts);
        if let Some(m) = &modules {
            scanners.retain(|s| m.iter().any(|x| x == s.name()));
            // Intrusif: hanya bila diminta eksplisit, dan hanya untuk localhost / domain dev yang diizinkan.
            let intr: Vec<String> = m.iter().filter(|x| appsec_core::intrusive::MODULES.contains(&x.as_str())).cloned().collect();
            if !intr.is_empty() {
                appsec_core::intrusive::check(target.kind.value(), &topts.intrusive_hosts).map_err(err)?;
                scanners.extend(appsec_core::intrusive::scanners(&intr, &topts.intrusive_hosts, topts.intrusive_rate));
            }
        }
        if scanners.is_empty() {
            return Err("Pilih minimal satu modul".into());
        }
        let token = appsec_core::cancel::Token::default();
        app.state::<Running>().0.lock().unwrap().insert(target_id, token.clone());
        let r = usecase::run_scan_cancellable(&*db, target_id, &scanners, &progress, &token).map_err(err);
        app.state::<Running>().0.lock().unwrap().remove(&target_id);
        r
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Scan terakhir tiap target (atau satu target saja), sudah dikorelasikan dengan pasangannya.
fn latest(db: &Db, only: Option<Uuid>) -> Res<Vec<(Target, Scan)>> {
    let mut out = vec![];
    for target in db.list().map_err(err)? {
        if let Some(scan) = db.latest(target.id).map_err(err)? {
            out.push((target, scan));
        }
    }
    // Korelasi butuh kedua sisi, jadi filter setelahnya.
    correlate::correlate_all(&mut out);
    out.retain(|(t, _)| only.is_none_or(|id| id == t.id));
    Ok(out)
}

#[derive(Serialize)]
struct TargetScan {
    target: Target,
    scan: Scan,
}

/// Untuk view temuan terpadu.
#[tauri::command]
fn latest_scans(db: State<Db>) -> Res<Vec<TargetScan>> {
    Ok(latest(&db, None)?.into_iter().map(|(target, scan)| TargetScan { target, scan }).collect())
}

/// Ringkasan semua scan untuk grafik tren & tab riwayat.
#[tauri::command]
fn scan_history(db: State<Db>) -> Res<Vec<appsec_core::sqlite::ScanSummary>> {
    db.history().map_err(err)
}

#[tauri::command]
fn get_tool_options(db: State<Db>) -> Res<ToolOptions> {
    db.setting("tools").map_err(err)
}

#[tauri::command]
fn set_tool_options(db: State<Db>, options: ToolOptions) -> Res<()> {
    db.set_setting("tools", &options).map_err(err)
}

/// Login GitHub (setting key "github"): token + username, untuk menaikkan limit API GitHub.
#[derive(Default, Serialize, Deserialize)]
struct GithubAuth { token: String, login: String }

/// Status login GitHub: username bila sudah login, else null. Tanpa jaringan.
#[tauri::command]
fn github_status(db: State<Db>) -> Res<Option<String>> {
    let a: GithubAuth = db.setting("github").map_err(err)?;
    Ok((!a.token.is_empty()).then_some(a.login))
}

/// Login GitHub dengan Personal Access Token: validasi ke GitHub, simpan, aktifkan. Kembalikan username.
#[tauri::command]
async fn github_sign_in(db: State<'_, Db>, token: String) -> Res<String> {
    let login = tauri::async_runtime::spawn_blocking(move || tools::github_login(&token).map(|l| (token, l)))
        .await
        .map_err(|e| e.to_string())?
        .map_err(err)?;
    db.set_setting("github", &GithubAuth { token: login.0.clone(), login: login.1.clone() }).map_err(err)?;
    tools::set_github_token(Some(login.0));
    Ok(login.1)
}

/// Logout GitHub: hapus token tersimpan dan nonaktifkan.
#[tauri::command]
fn github_sign_out(db: State<Db>) -> Res<()> {
    db.set_setting("github", &GithubAuth::default()).map_err(err)?;
    tools::set_github_token(None);
    Ok(())
}

/// Versi tiap tool (menjalankan `--version`, jadi di thread blocking).
#[tauri::command]
async fn tool_info() -> Res<Vec<tools::ToolInfo>> {
    tauri::async_runtime::spawn_blocking(|| tools::TOOLS.iter().map(|t| tools::info(t)).collect())
        .await
        .map_err(|e| e.to_string())
}

/// Versi program terbaru yang dirilis (butuh internet).
#[tauri::command]
async fn tool_latest(id: String) -> Res<String> {
    tauri::async_runtime::spawn_blocking(move || tools::latest(&id).map_err(err))
        .await
        .map_err(|e| e.to_string())?
}

/// Update program/data satu tool; log live lewat "scan-progress" dengan id "update-<tool>".
#[tauri::command]
async fn update_tool(app: AppHandle, tool: String) -> Res<String> {
    tauri::async_runtime::spawn_blocking(move || {
        let id = format!("update-{tool}");
        tools::update(&tool, &|msg| {
            let _ = app.emit("scan-progress", Progress { target_id: id.clone(), msg });
        })
        .map_err(err)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
fn get_dast_options(db: State<Db>) -> Res<DastOptions> {
    db.setting("dast").map_err(err)
}

#[tauri::command]
fn set_dast_options(db: State<Db>, options: DastOptions) -> Res<()> {
    db.set_setting("dast", &options).map_err(err)
}

#[tauri::command]
fn set_finding_status(db: State<Db>, id: Uuid, status: FindingStatus) -> Res<()> {
    db.set_status(id, status).map_err(err)
}

#[tauri::command]
fn report_markdown(db: State<Db>, target_id: Option<Uuid>) -> Res<String> {
    Ok(report::markdown(&latest(&db, target_id)?, chrono::Utc::now()))
}

/// Path berasal dari dialog simpan; ekstensi .md dipaksa.
#[tauri::command]
fn save_report(db: State<Db>, path: PathBuf, target_id: Option<Uuid>) -> Res<PathBuf> {
    let path = if path.extension().is_some_and(|e| e == "md") { path } else { path.with_extension("md") };
    std::fs::write(&path, report::markdown(&latest(&db, target_id)?, chrono::Utc::now())).map_err(|e| e.to_string())?;
    Ok(path)
}

/// Viewer laporan: hanya file Markdown, maksimal 5 MB.
#[tauri::command]
fn read_markdown(path: PathBuf) -> Res<String> {
    if !path.extension().is_some_and(|e| e == "md" || e == "markdown") {
        return Err("Hanya file .md yang bisa dibuka".into());
    }
    let meta = std::fs::metadata(&path).map_err(|e| e.to_string())?;
    if meta.len() > 5 * 1024 * 1024 {
        return Err("File terlalu besar (maks 5 MB)".into());
    }
    std::fs::read_to_string(&path).map_err(|e| e.to_string())
}

/// PDF dari tampilan laporan saat ini (CSS print: sidebar & kontrol disembunyikan), tanpa dialog cetak.
#[tauri::command]
async fn print_pdf(window: tauri::WebviewWindow, path: PathBuf) -> Res<PathBuf> {
    let path = if path.extension().is_some_and(|e| e == "pdf") { path } else { path.with_extension("pdf") };
    #[cfg(target_os = "linux")]
    {
        use gtk::glib;
        use webkit2gtk::PrintOperationExt;
        let uri = glib::filename_to_uri(&path, None).map_err(|e| e.to_string())?.to_string();
        let (tx, rx) = std::sync::mpsc::channel::<Res<()>>();
        window
            .with_webview(move |wv| {
                let settings = gtk::PrintSettings::new();
                // Nama printer file GTK ikut bahasa sistem, jadi pakai terjemahan GTK sendiri.
                settings.set_printer(&glib::dgettext(Some("gtk30"), "Print to File"));
                settings.set(gtk::PRINT_SETTINGS_OUTPUT_FILE_FORMAT, Some("pdf"));
                settings.set(gtk::PRINT_SETTINGS_OUTPUT_URI, Some(&uri));
                let setup = gtk::PageSetup::new();
                setup.set_paper_size(&gtk::PaperSize::new(Some(gtk::PAPER_NAME_A4)));
                let op = webkit2gtk::PrintOperation::builder()
                    .web_view(&wv.inner())
                    .print_settings(&settings)
                    .page_setup(&setup)
                    .build();
                let fail = tx.clone();
                op.connect_failed(move |_, e| {
                    let _ = fail.send(Err(e.to_string()));
                });
                // Klon `op` di closure menjaga objeknya hidup sampai cetak selesai.
                let keep = op.clone();
                op.connect_finished(move |_| {
                    let _ = &keep;
                    let _ = tx.send(Ok(()));
                });
                op.print();
            })
            .map_err(|e| e.to_string())?;
        tauri::async_runtime::spawn_blocking(move || rx.recv_timeout(std::time::Duration::from_secs(120)))
            .await
            .map_err(|e| e.to_string())?
            .map_err(|_| "Generate PDF tidak selesai (timeout)".to_string())??;
        Ok(path)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (window, path);
        Err("Generate PDF saat ini hanya tersedia di Linux".into())
    }
}

/// Markdown -> HTML di Rust: `marked` di JSC (WebKitGTK) macet pada laporan besar. Hasilnya tetap disanitasi di UI.
#[tauri::command]
async fn markdown_html(md: String) -> String {
    use pulldown_cmark::{Options, Parser, html};
    let mut out = String::with_capacity(md.len() * 3 / 2);
    html::push_html(&mut out, Parser::new_ext(&md, Options::ENABLE_TABLES | Options::ENABLE_STRIKETHROUGH));
    out
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let data = app.path().app_data_dir()?;
            // Binary hasil "Update" di Pengaturan; dipakai lebih dulu daripada sidecar bawaan.
            std::fs::create_dir_all(data.join("tools"))?;
            tools::set_dir(data.join("tools"));
            let db = Db::open(&data.join("appsec.db"))?;
            // Aktifkan token GitHub tersimpan (login dari sesi sebelumnya).
            if let Ok(a) = db.setting::<GithubAuth>("github") {
                tools::set_github_token((!a.token.is_empty()).then_some(a.token));
            }
            app.manage(db);
            app.manage(Running::default());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![list_targets, add_target, remove_target, run_scan, latest_scans,
            report_markdown, save_report, read_markdown, set_finding_status,
            get_dast_options, set_dast_options, link_target, markdown_html, scan_history, print_pdf,
            get_tool_options, set_tool_options, tool_info, update_tool, tool_latest, cancel_scan, export_sbom,
            github_status, github_sign_in, github_sign_out])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
