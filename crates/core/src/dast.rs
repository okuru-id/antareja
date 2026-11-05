//! Engine DAST native: headers, TLS, port, file sensitif. Non-intrusif: hanya GET biasa & TCP connect.
use crate::domain::{Finding, ScanMode, Scanner, Severity};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use reqwest::blocking::{Client, Response};
use reqwest::redirect::Policy;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::path::Path;
use std::time::Duration;
use url::Url;

/// Modul opsional (P2), default mati. Field baru wajib default agar setting lama tetap terbaca.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct DastOptions {
    /// Template nuclei (lambat: bisa beberapa menit).
    pub nuclei: bool,
    /// Second opinion dari Mozilla HTTP Observatory: hostname dikirim ke pihak ketiga.
    pub online: bool,
    /// Analisis TLS mendalam dengan testssl.sh.
    pub testssl: bool,
    /// Port + versi layanan dengan nmap (pengganti modul Ports).
    pub nmap: bool,
    /// OWASP ZAP baseline (spider + passive scan).
    pub zap: bool,
}

pub fn default_scanners(opts: DastOptions, tools: &crate::tools::ToolOptions) -> Vec<Box<dyn Scanner>> {
    let mut v: Vec<Box<dyn Scanner>> = vec![Box::new(Headers), Box::new(Tls), Box::new(Ports), Box::new(Files)];
    if opts.nuclei {
        v.push(Box::new(Nuclei { tags: tools.nuclei_tags.clone(), rate: tools.nuclei_rate.clamp(1, 500).to_string(), crawl: tools.nuclei_crawl }));
    }
    if opts.online {
        v.push(Box::new(Observatory));
    }
    if opts.testssl {
        v.push(Box::new(Testssl));
    }
    if opts.nmap {
        v.push(Box::new(Nmap));
    }
    if opts.zap {
        v.push(Box::new(Zap { active: false }));
    }
    v
}

const TIMEOUT: Duration = Duration::from_secs(10);

fn finding(tool: &str, severity: Severity, rule_id: &str) -> Finding {
    Finding::new(ScanMode::Dast, tool, severity, rule_id)
}

fn client(follow_redirects: bool) -> Result<Client> {
    Ok(Client::builder()
        .timeout(TIMEOUT)
        .user_agent(concat!("AppSecScanner/", env!("CARGO_PKG_VERSION")))
        // Validitas sertifikat dinilai modul TLS; modul lain tetap jalan walau sertifikat bermasalah.
        .tls_danger_accept_invalid_certs(true)
        .redirect(if follow_redirects { Policy::limited(5) } else { Policy::none() })
        .build()?)
}

/// Baca body maksimal 64 KB (cukup untuk deteksi, tidak menyedot file besar).
fn body(resp: Response) -> String {
    let mut buf = vec![];
    let _ = resp.take(64 * 1024).read_to_end(&mut buf);
    String::from_utf8_lossy(&buf).into_owned()
}

/// Evidence dibatasi supaya DB & laporan tidak membengkak.
pub(crate) fn clip(s: &str) -> String {
    const MAX: usize = 2000;
    match s.char_indices().nth(MAX) {
        Some((i, _)) => format!("{}\n… (dipotong)", &s[..i]),
        None => s.to_string(),
    }
}

/// Ringkasan respons HTTP: baris status + header (nilai cookie disamarkan).
fn http_evidence(method: &str, url: &str, r: &Response) -> String {
    let mut e = format!("{method} {url} → {} {}\n", r.status().as_u16(), r.status().canonical_reason().unwrap_or_default());
    for (k, v) in r.headers() {
        let v = v.to_str().unwrap_or("<biner>");
        let v = if k == "set-cookie" { mask_cookie(v) } else { v.to_string() };
        e += &format!("{k}: {v}\n");
    }
    e
}

fn mask_cookie(c: &str) -> String {
    let (pair, attrs) = c.split_once(';').unwrap_or((c, ""));
    let name = pair.split('=').next().unwrap_or(pair);
    if attrs.is_empty() { format!("{name}=****") } else { format!("{name}=****;{attrs}") }
}

fn host_port(target: &str) -> Result<(Url, String, u16)> {
    let u = Url::parse(target)?;
    let host = u.host_str().context("URL tanpa host")?.trim_matches(['[', ']']).to_string();
    let port = u.port_or_known_default().context("port tidak diketahui")?;
    Ok((u, host, port))
}

fn connect(host: &str, port: u16, timeout: Duration) -> Result<TcpStream> {
    let addr = (host, port).to_socket_addrs()?.next().context("host tidak bisa di-resolve")?;
    let s = TcpStream::connect_timeout(&addr, timeout)?;
    s.set_read_timeout(Some(timeout))?;
    s.set_write_timeout(Some(timeout))?;
    Ok(s)
}

// ---------------- Security headers ----------------

pub struct Headers;

/// (header, severity, kenapa berbahaya, contoh nilai)
const HEADER_CHECKS: &[(&str, Severity, &str, &str)] = &[
    ("Strict-Transport-Security", Severity::Medium,
        "Browser masih mau membuka versi HTTP, jadi penyerang di jaringan yang sama (Wi-Fi publik) bisa melakukan downgrade / SSL stripping dan menyadap cookie.",
        "Strict-Transport-Security: max-age=31536000; includeSubDomains"),
    ("Content-Security-Policy", Severity::Medium,
        "Tanpa CSP, satu celah XSS langsung bisa menjalankan script apa pun dan mengirim data ke domain mana pun.",
        "Content-Security-Policy: default-src 'self'; frame-ancestors 'none'\n(uji dulu dengan Content-Security-Policy-Report-Only)"),
    ("X-Content-Type-Options", Severity::Low,
        "Browser bisa menebak (sniff) tipe konten, misalnya file upload diperlakukan sebagai script.",
        "X-Content-Type-Options: nosniff"),
    ("X-Frame-Options", Severity::Medium,
        "Halaman bisa dimuat di iframe situs lain untuk clickjacking (user tertipu mengklik tombol di halaman Anda).",
        "X-Frame-Options: DENY\n(atau CSP: frame-ancestors 'none')"),
    ("Referrer-Policy", Severity::Low,
        "URL lengkap, termasuk token di query string, bisa bocor ke situs pihak ketiga lewat header Referer.",
        "Referrer-Policy: strict-origin-when-cross-origin"),
    ("Permissions-Policy", Severity::Info,
        "Akses fitur browser sensitif (kamera, mikrofon, lokasi) tidak dibatasi untuk script / iframe pihak ketiga.",
        "Permissions-Policy: camera=(), microphone=(), geolocation=()"),
];

impl Scanner for Headers {
    fn name(&self) -> &str { "Headers" }
    fn scan(&self, target: &str, _log: &dyn Fn(&str)) -> Result<Vec<Finding>> {
        let resp = client(true)?.get(target).send()?;
        let url = resp.url().to_string();
        let ev = http_evidence("GET", &url, &resp);
        let https = resp.url().scheme() == "https";
        let h = resp.headers();
        let get = |k: &str| h.get(k).and_then(|v| v.to_str().ok()).unwrap_or_default().to_ascii_lowercase();
        let mut out = vec![];

        for &(name, sev, why, fix) in HEADER_CHECKS {
            let present = h.contains_key(name)
                || (name == "X-Frame-Options" && get("content-security-policy").contains("frame-ancestors"));
            if present || (name == "Strict-Transport-Security" && !https) {
                continue; // HSTS tak berlaku di HTTP; modul TLS yang melaporkan
            }
            out.push(Finding {
                title: format!("Header {name} tidak dipasang"),
                location: url.clone(),
                description: format!("Response tidak mengirim header keamanan {name}."),
                impact: why.into(),
                recommendation: format!("Tambahkan di web server / reverse proxy:\n{fix}"),
                evidence: clip(&format!("{ev}{}: (tidak ada)", name.to_ascii_lowercase())),
                ..finding("Headers", sev, name)
            });
        }

        let leaks: Vec<String> = ["server", "x-powered-by", "x-aspnet-version"]
            .into_iter()
            .filter_map(|k| h.get(k)?.to_str().ok().filter(|v| v.chars().any(|c| c.is_ascii_digit())).map(|v| format!("{k}: {v}")))
            .collect();
        if !leaks.is_empty() {
            out.push(Finding {
                title: "Versi software server terekspos".into(),
                location: url.clone(),
                description: leaks.join("\n"),
                impact: "Penyerang bisa langsung mencocokkan versi ini dengan daftar CVE yang diketahui.".into(),
                recommendation: "Sembunyikan versi: nginx `server_tokens off;`, Apache `ServerTokens Prod`, PHP `expose_php = Off`.".into(),
                evidence: clip(&ev),
                ..finding("Headers", Severity::Low, "version-disclosure")
            });
        }

        let weak: Vec<String> = h
            .get_all("set-cookie")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .filter_map(|c| {
                let l = c.to_ascii_lowercase();
                let mut miss = vec![];
                if https && !l.contains("secure") { miss.push("Secure"); }
                if !l.contains("httponly") { miss.push("HttpOnly"); }
                if !l.contains("samesite") { miss.push("SameSite"); }
                let name = c.split('=').next().unwrap_or(c);
                (!miss.is_empty()).then(|| format!("{name}: tanpa {}", miss.join(", ")))
            })
            .collect();
        if !weak.is_empty() {
            out.push(Finding {
                title: "Cookie tanpa atribut keamanan".into(),
                location: url,
                description: weak.join("\n"),
                impact: "Tanpa HttpOnly cookie bisa dicuri lewat XSS; tanpa Secure ikut terkirim lewat HTTP; tanpa SameSite rawan CSRF.".into(),
                recommendation: "Set cookie sesi dengan `Secure; HttpOnly; SameSite=Lax` (Laravel: SESSION_SECURE_COOKIE=true).".into(),
                evidence: clip(&ev),
                ..finding("Headers", Severity::Low, "cookie-flags")
            });
        }
        Ok(out)
    }
}

// ---------------- TLS / HTTPS ----------------

pub struct Tls;

impl Scanner for Tls {
    fn name(&self) -> &str { "TLS" }
    fn scan(&self, target: &str, _log: &dyn Fn(&str)) -> Result<Vec<Finding>> {
        let (u, host, port) = host_port(target)?;
        let tls = |sev, rule: &str| finding("TLS", sev, rule);
        if u.scheme() == "http" {
            return Ok(vec![Finding {
                title: "Situs diakses lewat HTTP tanpa enkripsi".into(),
                location: target.into(),
                description: "Target memakai http://, semua lalu lintas (termasuk password dan cookie) terkirim tanpa enkripsi.".into(),
                impact: "Siapa pun di jalur jaringan bisa membaca atau mengubah data.".into(),
                recommendation: "Pasang sertifikat (mis. Let's Encrypt), layani lewat HTTPS, alihkan HTTP ke HTTPS, lalu daftarkan target dengan https://.".into(),
                evidence: format!("URL target: {target}\nskema: http (tanpa TLS)"),
                ..tls(Severity::High, "no-https")
            }]);
        }

        let mut out = vec![];
        let (verify_err, not_after, cert_ev) = handshake(&host, port)?;
        if let Some(e) = verify_err {
            out.push(Finding {
                title: "Sertifikat TLS tidak valid".into(),
                location: target.into(),
                evidence: format!("{cert_ev}\nhasil validasi: {e}"),
                description: e,
                impact: "Browser menampilkan peringatan; user yang terbiasa meng-klik \"lanjutkan\" jadi rentan man-in-the-middle.".into(),
                recommendation: "Pakai sertifikat dari CA tepercaya yang cocok dengan nama host dan sertakan rantai intermediate lengkap.".into(),
                ..tls(Severity::High, "cert-invalid")
            });
        }
        let days = (not_after - chrono::Utc::now().timestamp()) / 86_400;
        if days < 30 {
            out.push(Finding {
                title: if days < 0 { "Sertifikat TLS sudah kedaluwarsa".into() } else { format!("Sertifikat TLS kedaluwarsa dalam {days} hari") },
                location: target.into(),
                description: format!("Masa berlaku berakhir {}.", chrono::DateTime::from_timestamp(not_after, 0).unwrap_or_default().format("%Y-%m-%d")),
                impact: "Setelah kedaluwarsa, browser memblokir situs dan integrasi API berhenti.".into(),
                recommendation: "Perpanjang sertifikat dan aktifkan pembaruan otomatis (certbot renew / cert-manager).".into(),
                evidence: cert_ev.clone(),
                ..tls(if days < 0 { Severity::High } else { Severity::Medium }, "cert-expiry")
            });
        }

        for (minor, name) in [(1u8, "TLS 1.0"), (2, "TLS 1.1")] {
            if legacy_tls_supported(&host, port, minor).unwrap_or(false) {
                out.push(Finding {
                    title: format!("Server masih menerima {name}"),
                    location: format!("{host}:{port}"),
                    description: format!("Handshake {name} diterima server."),
                    impact: "Protokol lama ini sudah deprecated (RFC 8996) dan punya kelemahan kriptografi yang diketahui.".into(),
                    recommendation: "Batasi ke TLS 1.2 dan 1.3 saja. nginx: `ssl_protocols TLSv1.2 TLSv1.3;`".into(),
                    evidence: format!("ClientHello {name} (versi 0x030{}) → {host}:{port}\nServerHello diterima dengan versi 0x030{} (handshake {name} disetujui server)", minor + 1, minor + 1),
                    ..tls(Severity::Medium, &format!("tls1{minor}"))
                });
            }
        }

        // HTTP -> HTTPS hanya bisa dicek kalau HTTPS di port standar.
        let http_url = format!("http://{}/", u.host_str().unwrap_or(&host));
        if port == 443
            && let Ok(r) = client(false)?.get(&http_url).send()
        {
            let ev = http_evidence("GET", &http_url, &r);
            let loc = r.headers().get("location").and_then(|v| v.to_str().ok()).unwrap_or_default();
            if !(r.status().is_redirection() && loc.starts_with("https://")) {
                out.push(Finding {
                    title: "HTTP tidak dialihkan ke HTTPS".into(),
                    location: format!("http://{host}/"),
                    description: format!("Port 80 menjawab dengan status {} tanpa redirect ke HTTPS.", r.status()),
                    impact: "User yang mengetik alamat tanpa https:// tetap memakai koneksi tanpa enkripsi.".into(),
                    recommendation: "Redirect permanen (301) semua request HTTP ke HTTPS, lalu pasang HSTS.".into(),
                    evidence: clip(&ev),
                    ..tls(Severity::Medium, "no-https-redirect")
                });
            }
        }
        Ok(out)
    }
}

/// Verifier yang mencatat hasil validasi WebPKI tapi tetap melanjutkan handshake,
/// supaya detail sertifikat tetap bisa dibaca walau tidak valid.
#[derive(Debug)]
struct Recorder {
    inner: Arc<rustls::client::WebPkiServerVerifier>,
    err: Mutex<Option<String>>,
}

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

impl ServerCertVerifier for Recorder {
    fn verify_server_cert(&self, end: &CertificateDer, inter: &[CertificateDer], name: &ServerName, ocsp: &[u8], now: UnixTime)
        -> Result<ServerCertVerified, rustls::Error> {
        if let Err(e) = self.inner.verify_server_cert(end, inter, name, ocsp, now) {
            *self.err.lock().unwrap() = Some(e.to_string());
        }
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, m: &[u8], c: &CertificateDer, d: &rustls::DigitallySignedStruct)
        -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(m, c, d)
    }
    fn verify_tls13_signature(&self, m: &[u8], c: &CertificateDer, d: &rustls::DigitallySignedStruct)
        -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(m, c, d)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Handshake TLS modern -> (error validasi sertifikat, not_after unix, ringkasan sertifikat untuk evidence).
fn handshake(host: &str, port: u16) -> Result<(Option<String>, i64, String)> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    // CA sistem ikut dipercaya: aplikasi internal sering pakai CA perusahaan.
    roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
    let inner = rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone()).build()?;
    let rec = Arc::new(Recorder { inner, err: Mutex::new(None) });
    let cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(rec.clone())
        .with_no_client_auth();
    let mut conn = rustls::ClientConnection::new(Arc::new(cfg), ServerName::try_from(host.to_string())?)?;
    let mut sock = connect(host, port, TIMEOUT)?;
    while conn.is_handshaking() {
        conn.complete_io(&mut sock).context("handshake TLS gagal")?;
    }
    let der = conn.peer_certificates().and_then(|c| c.first()).context("server tidak mengirim sertifikat")?;
    let (_, cert) = x509_parser::parse_x509_certificate(der).map_err(|e| anyhow::anyhow!("sertifikat tidak bisa dibaca: {e}"))?;
    let err = rec.err.lock().unwrap().take();
    let v = cert.validity();
    let san = cert.subject_alternative_name().ok().flatten()
        .map(|s| s.value.general_names.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(", "))
        .unwrap_or_default();
    let ev = format!(
        "koneksi: {host}:{port} · {:?} · {:?}\nsubject: {}\nissuer: {}\nSAN: {}\nberlaku: {} s/d {}",
        conn.protocol_version().unwrap_or(rustls::ProtocolVersion::Unknown(0)),
        conn.negotiated_cipher_suite().map(|c| c.suite()).unwrap_or(rustls::CipherSuite::Unknown(0)),
        cert.subject(), cert.issuer(), if san.is_empty() { "-" } else { &san },
        v.not_before.to_datetime().date(), v.not_after.to_datetime().date(),
    );
    Ok((err, v.not_after.timestamp(), ev))
}

/// rustls tidak mendukung TLS < 1.2, jadi kirim ClientHello TLS 1.0/1.1 manual
/// dan lihat apakah server membalas ServerHello dengan versi yang sama.
fn legacy_tls_supported(host: &str, port: u16, minor: u8) -> Result<bool> {
    let be16 = |n: usize| (n as u16).to_be_bytes();
    let mut ext = vec![];
    if host.parse::<IpAddr>().is_err() {
        let h = host.as_bytes();
        ext.extend([0, 0]); // server_name
        ext.extend(be16(h.len() + 5));
        ext.extend(be16(h.len() + 3));
        ext.push(0);
        ext.extend(be16(h.len()));
        ext.extend(h);
    }
    ext.extend([0, 0x0a, 0, 6, 0, 4, 0, 0x17, 0, 0x18]); // supported_groups: P-256, P-384
    ext.extend([0, 0x0b, 0, 2, 1, 0]); // ec_point_formats: uncompressed
    let suites: [u16; 9] = [0xc014, 0xc013, 0xc00a, 0xc009, 0x0039, 0x0033, 0x0035, 0x002f, 0x000a];

    let mut hello = vec![3, minor];
    hello.extend(uuid::Uuid::new_v4().as_bytes());
    hello.extend(uuid::Uuid::new_v4().as_bytes()); // 32 byte random
    hello.push(0); // session id kosong
    hello.extend(be16(suites.len() * 2));
    suites.iter().for_each(|s| hello.extend(s.to_be_bytes()));
    hello.extend([1, 0]); // compression: null
    hello.extend(be16(ext.len()));
    hello.extend(ext);

    let mut msg = vec![0x16, 3, 1];
    msg.extend(be16(hello.len() + 4));
    msg.push(1); // ClientHello
    msg.extend(&(hello.len() as u32).to_be_bytes()[1..]);
    msg.extend(hello);

    let mut s = connect(host, port, TIMEOUT)?;
    s.write_all(&msg)?;
    let mut hdr = [0u8; 11]; // record(5) + handshake type(1) + len(3) + version(2)
    Ok(s.read_exact(&mut hdr).is_ok() && hdr[0] == 0x16 && hdr[5] == 2 && hdr[9] == 3 && hdr[10] == minor)
}

// ---------------- Port berisiko ----------------

pub struct Ports;

// ponytail: daftar tetap; jadikan setting kalau tim butuh port custom.
const PORTS: &[(u16, &str, Severity)] = &[
    (21, "FTP", Severity::Medium),
    (23, "Telnet", Severity::High),
    (445, "SMB", Severity::High),
    (1433, "MS SQL Server", Severity::High),
    (1521, "Oracle DB", Severity::High),
    (2375, "Docker API tanpa TLS", Severity::Critical),
    (2379, "etcd", Severity::High),
    (3306, "MySQL / MariaDB", Severity::High),
    (3389, "Remote Desktop (RDP)", Severity::High),
    (5432, "PostgreSQL", Severity::High),
    (5601, "Kibana", Severity::Medium),
    (5900, "VNC", Severity::High),
    (5984, "CouchDB", Severity::High),
    (6379, "Redis", Severity::High),
    (8086, "InfluxDB", Severity::Medium),
    (9000, "PHP-FPM / Portainer", Severity::Medium),
    (9200, "Elasticsearch", Severity::High),
    (10250, "Kubelet API", Severity::High),
    (11211, "Memcached", Severity::High),
    (15672, "RabbitMQ Management", Severity::Medium),
    (27017, "MongoDB", Severity::High),
];

impl Scanner for Ports {
    fn name(&self) -> &str { "Ports" }
    fn scan(&self, target: &str, log: &dyn Fn(&str)) -> Result<Vec<Finding>> {
        let (_, host, _) = host_port(target)?;
        let timeout = Duration::from_secs(3);
        let mut out = vec![];
        // Proxy/CDN (mis. Cloudflare) atau firewall bisa menerima TCP di semua port: uji port kanari yang mustahil dipakai.
        let canary = [47_123u16, 61_987].into_iter().find(|&p| connect(&host, p, timeout).is_ok());
        if let Some(p) = canary {
            log(&format!("port kanari {p} ikut tersambung: host menerima semua port, hanya layanan yang menjawab yang dilaporkan"));
            out.push(Finding {
                title: "Hasil scan port terbatas: host menerima koneksi di semua port".into(),
                location: host.clone(),
                description: format!("Port acak {p} (tidak dipakai layanan apa pun) ikut tersambung. Biasanya ini proxy/CDN (mis. Cloudflare) atau firewall yang menjawab semua koneksi, jadi \"TCP terhubung\" tidak membuktikan port terbuka."),
                impact: "Port hanya dilaporkan kalau layanannya benar-benar menjawab. Port di server origin di balik proxy tidak terlihat dari sini.".into(),
                recommendation: "Scan IP origin langsung (dari jaringan yang diizinkan) untuk hasil port yang akurat.".into(),
                evidence: format!("TCP connect {host}:{p} → terhubung (port kanari, seharusnya tertutup)"),
                ..finding("Ports", Severity::Info, "port-accept-all")
            });
        }
        // Concurrency dibatasi 8 koneksi sekaligus agar tidak membanjiri target.
        for chunk in PORTS.chunks(8) {
            let open: Vec<_> = std::thread::scope(|s| {
                let host = &host;
                let hs: Vec<_> = chunk.iter().map(|p| s.spawn(move || {
                    let t = std::time::Instant::now();
                    let mut c = connect(host, p.0, timeout).ok()?;
                    let ms = t.elapsed().as_millis();
                    // Redis tidak kirim banner; layanan lain (FTP, MySQL, SSH, ...) biasanya menyapa duluan.
                    let banner = if p.0 == 6379 { String::new() } else { read_banner(&mut c) };
                    Some((p, c, ms, banner))
                })).collect();
                hs.into_iter().filter_map(|h| h.join().ok().flatten()).collect()
            });
            for (&(port, svc, sev), mut conn, ms, banner) in open {
                let no_auth = port == 6379 && redis_no_auth(&mut conn);
                if canary.is_some() && banner.is_empty() && !no_auth {
                    continue;
                }
                log(&format!("port {port} ({svc}) terbuka"));
                let mut ev = format!("TCP connect {host}:{port} → terhubung ({ms} ms)");
                if port == 6379 {
                    ev += if no_auth { "\nPING → +PONG (tanpa AUTH)" } else { "\nPING → ditolak / butuh AUTH" };
                } else if !banner.is_empty() {
                    ev += &format!("\nbanner: {banner}");
                }
                out.push(Finding {
                    title: if no_auth { "Redis terbuka tanpa autentikasi".into() } else { format!("Port {port} ({svc}) terbuka ke publik") },
                    location: format!("{host}:{port}"),
                    description: if no_auth {
                        "Perintah PING dijawab +PONG tanpa login.".into()
                    } else {
                        format!("Koneksi TCP ke port {port} berhasil dari luar.")
                    },
                    impact: format!("{svc} bisa dijangkau langsung dari internet. Layanan ini seharusnya hanya di jaringan internal; kalau autentikasinya lemah atau tidak ada, data bisa dibaca, diubah, atau dihapus siapa pun."),
                    recommendation: format!("Tutup port {port} di firewall / security group, bind layanan ke 127.0.0.1 atau jaringan privat, dan akses lewat VPN / SSH tunnel."),
                    evidence: ev,
                    ..finding("Ports", if no_auth { Severity::Critical } else { sev }, &format!("port-{port}"))
                });
            }
        }
        Ok(out)
    }
}

/// Sapaan awal layanan (maks 1,5 detik, 200 byte).
fn read_banner(c: &mut TcpStream) -> String {
    let _ = c.set_read_timeout(Some(Duration::from_millis(1500)));
    let mut buf = [0u8; 200];
    let n = c.read(&mut buf).unwrap_or(0);
    let _ = c.set_read_timeout(Some(Duration::from_secs(3)));
    // Protokol biner (MySQL, RDP): ambil potongan teks yang terbaca saja.
    String::from_utf8_lossy(&buf[..n])
        .split(|c: char| !(c.is_ascii_graphic() || c == ' '))
        .map(str::trim)
        .filter(|t| t.len() >= 4)
        .collect::<Vec<_>>()
        .join(" · ")
}

fn redis_no_auth(conn: &mut TcpStream) -> bool {
    let mut buf = [0u8; 5];
    conn.write_all(b"PING\r\n").is_ok() && conn.read_exact(&mut buf).is_ok() && &buf == b"+PONG"
}

// ---------------- File & path sensitif ----------------

pub struct Files;

struct Probe {
    path: &'static str,
    sev: Severity,
    title: &'static str,
    /// Cek isi body supaya halaman "soft 404" tidak dianggap temuan.
    matches: fn(&str) -> bool,
    /// true = status apa pun (untuk halaman error debug), false = hanya 200.
    any_status: bool,
    why: &'static str,
    fix: &'static str,
}

fn env_like(b: &str) -> bool {
    !b.contains("<html")
        && b.lines()
            .filter(|l| l.split_once('=').is_some_and(|(k, _)| !k.is_empty() && k.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')))
            .count() >= 2
}
fn sql_dump(b: &str) -> bool {
    let u = b.to_ascii_uppercase();
    !u.contains("<HTML") && (u.contains("CREATE TABLE") || u.contains("INSERT INTO"))
}
fn dir_listing(b: &str) -> bool {
    b.contains("<title>Index of /") || b.contains("<title>Directory listing for /")
}
fn debug_page(b: &str) -> bool {
    [
        "Whoops, looks like something went wrong", "Ignition", "Symfony\\Component\\", "at Illuminate\\",
        "Traceback (most recent call last)", "Werkzeug Debugger", "You're seeing this error because you have DEBUG = True",
        "ActionController::RoutingError", "Stack trace:", "Exception in thread",
    ]
    .iter()
    .any(|m| b.contains(m))
}

/// Beberapa baris awal isi file sebagai bukti; nilai rahasia disamarkan.
fn excerpt(path: &str, b: &str) -> String {
    let lines: Vec<&str> = if path == "/appsec-scanner-not-found-check" {
        // Halaman debug: tampilkan baris yang memuat penanda debug-nya.
        b.lines().filter(|l| debug_page(l)).take(5).collect()
    } else {
        b.lines().filter(|l| !l.trim().is_empty()).take(8).collect()
    };
    lines.iter().map(|l| {
        let l = l.trim();
        let l = match path {
            "/.env" | "/actuator/env" => l.split_once('=').map_or(l.to_string(), |(k, _)| format!("{k}=****")),
            "/.htpasswd" => l.split_once(':').map_or(l.to_string(), |(u, _)| format!("{u}:****")),
            _ if l.to_ascii_uppercase().starts_with("INSERT INTO") => {
                let u = l.to_ascii_uppercase();
                u.find(" VALUES").or(u.find('(')).map_or(l.to_string(), |i| format!("{} … (data disamarkan)", &l[..i]))
            }
            _ => l.to_string(),
        };
        l.chars().take(160).collect::<String>()
    }).collect::<Vec<_>>().join("\n")
}

const PROBES: &[Probe] = &[
    Probe { path: "/.env", sev: Severity::Critical, title: "File .env bisa diunduh", matches: env_like, any_status: false,
        why: "Berisi kredensial database, API key, dan APP_KEY. Dengan APP_KEY Laravel, penyerang bisa memalsukan session bahkan RCE.",
        fix: "Arahkan document root ke folder public/ (bukan root project), blokir dotfile di web server (nginx: `location ~ /\\. { deny all; }`), lalu rotasi semua secret di dalamnya." },
    Probe { path: "/.git/HEAD", sev: Severity::High, title: "Folder .git ter-expose", matches: |b| b.starts_with("ref: "), any_status: false,
        why: "Seluruh source code dan riwayat commit (termasuk secret lama) bisa direkonstruksi dengan tool seperti git-dumper.",
        fix: "Jangan deploy folder .git ke server, atau blokir akses ke dotfile di web server." },
    Probe { path: "/backup.sql", sev: Severity::Critical, title: "Dump database bisa diunduh (backup.sql)", matches: sql_dump, any_status: false,
        why: "Dump database berisi seluruh data aplikasi, termasuk data pribadi dan hash password.",
        fix: "Hapus file backup dari web root dan simpan backup di storage terpisah yang tidak bisa diakses publik." },
    Probe { path: "/dump.sql", sev: Severity::Critical, title: "Dump database bisa diunduh (dump.sql)", matches: sql_dump, any_status: false,
        why: "Dump database berisi seluruh data aplikasi, termasuk data pribadi dan hash password.",
        fix: "Hapus file backup dari web root dan simpan backup di storage terpisah yang tidak bisa diakses publik." },
    Probe { path: "/database.sql", sev: Severity::Critical, title: "Dump database bisa diunduh (database.sql)", matches: sql_dump, any_status: false,
        why: "Dump database berisi seluruh data aplikasi, termasuk data pribadi dan hash password.",
        fix: "Hapus file backup dari web root dan simpan backup di storage terpisah yang tidak bisa diakses publik." },
    Probe { path: "/phpinfo.php", sev: Severity::Medium, title: "Halaman phpinfo() terbuka", matches: |b| b.contains("PHP Version") && b.contains("phpinfo"), any_status: false,
        why: "Membocorkan versi PHP, modul, path server, dan environment variable (bisa termasuk secret).",
        fix: "Hapus file phpinfo dari server produksi." },
    Probe { path: "/info.php", sev: Severity::Medium, title: "Halaman phpinfo() terbuka (info.php)", matches: |b| b.contains("PHP Version") && b.contains("phpinfo"), any_status: false,
        why: "Membocorkan versi PHP, modul, path server, dan environment variable (bisa termasuk secret).",
        fix: "Hapus file phpinfo dari server produksi." },
    Probe { path: "/storage/logs/laravel.log", sev: Severity::High, title: "Log Laravel bisa diunduh", matches: |b| b.contains(".ERROR:") || b.contains("Stack trace"), any_status: false,
        why: "Log berisi stack trace, query, path internal, dan kadang data user atau token.",
        fix: "Pastikan document root = public/, bukan root project Laravel." },
    Probe { path: "/.htpasswd", sev: Severity::High, title: "File .htpasswd bisa diunduh", matches: |b| ["$apr1$", "$2y$", "{SHA}"].iter().any(|m| b.contains(m)), any_status: false,
        why: "Hash password bisa di-crack offline.",
        fix: "Simpan .htpasswd di luar web root dan blokir akses dotfile." },
    Probe { path: "/.DS_Store", sev: Severity::Low, title: "File .DS_Store ter-expose", matches: |b| b.contains("Bud1"), any_status: false,
        why: "Membocorkan daftar nama file dan folder, termasuk yang tidak di-link.",
        fix: "Hapus .DS_Store dari deploy dan tambahkan ke .gitignore." },
    Probe { path: "/actuator/env", sev: Severity::High, title: "Spring Boot Actuator /env terbuka", matches: |b| b.contains("propertySources"), any_status: false,
        why: "Menampilkan seluruh konfigurasi dan environment, sering termasuk kredensial.",
        // Teks saran perbaikan, bukan konfigurasi Spring yang aktif.
        // nosemgrep: java.spring.security.audit.spring-actuator-non-health-enabled.spring-actuator-dangerous-endpoints-enabled
        fix: "Batasi endpoint actuator: `management.endpoints.web.exposure.include=health` dan lindungi dengan auth." },
    Probe { path: "/server-status", sev: Severity::Low, title: "Apache server-status terbuka", matches: |b| b.contains("Apache Server Status"), any_status: false,
        why: "Menampilkan request yang sedang berjalan, termasuk URL dan IP klien.",
        fix: "Batasi mod_status hanya untuk 127.0.0.1 (`Require local`)." },
    Probe { path: "/", sev: Severity::Medium, title: "Directory listing aktif", matches: dir_listing, any_status: false,
        why: "Siapa pun bisa melihat dan mengunduh semua file di folder tersebut.",
        fix: "Matikan autoindex (nginx `autoindex off;`, Apache `Options -Indexes`)." },
    Probe { path: "/uploads/", sev: Severity::Medium, title: "Directory listing aktif (/uploads/)", matches: dir_listing, any_status: false,
        why: "Siapa pun bisa melihat dan mengunduh semua file upload, termasuk dokumen user.",
        fix: "Matikan autoindex (nginx `autoindex off;`, Apache `Options -Indexes`)." },
    Probe { path: "/_ignition/health-check", sev: Severity::High, title: "Laravel Ignition aktif (APP_DEBUG=true)", matches: |b| b.contains("can_execute_commands"), any_status: false,
        why: "Mode debug di produksi membocorkan stack trace dan konfigurasi; versi Ignition lama rentan RCE (CVE-2021-3129).",
        fix: "Set APP_DEBUG=false dan APP_ENV=production di .env produksi, lalu `php artisan config:cache`." },
    Probe { path: "/appsec-scanner-not-found-check", sev: Severity::High, title: "Mode debug aktif (halaman error detail)", matches: debug_page, any_status: true,
        why: "Halaman error debug membocorkan stack trace, path server, potongan source code, dan kadang environment variable.",
        fix: "Matikan mode debug di produksi (Laravel APP_DEBUG=false, Django DEBUG=False, Flask debug=False)." },
];

impl Scanner for Files {
    fn name(&self) -> &str { "Files" }
    fn scan(&self, target: &str, log: &dyn Fn(&str)) -> Result<Vec<Finding>> {
        let c = client(false)?;
        let base = target.trim_end_matches('/');
        let mut out = vec![];
        // ponytail: berurutan (±16 request) supaya ramah ke target; paralelkan kalau daftar membesar.
        for p in PROBES {
            let url = format!("{base}{}", p.path);
            let Ok(r) = c.get(&url).send() else { continue };
            let head = http_evidence("GET", &url, &r);
            let ok = p.any_status || r.status().is_success();
            let b = body(r);
            if !ok || !(p.matches)(&b) {
                continue;
            }
            log(&format!("{} terekspos", p.path));
            out.push(Finding {
                title: p.title.into(),
                location: url,
                description: format!("{} bisa diakses publik dan isinya terkonfirmasi.", p.path),
                impact: p.why.into(),
                recommendation: p.fix.into(),
                evidence: clip(&format!("{head}\n--- potongan isi ({} byte dibaca) ---\n{}", b.len(), excerpt(p.path, &b))),
                ..finding("Files", p.sev, p.path)
            });
        }
        Ok(out)
    }
}

// ---------------- Nuclei (opsional) ----------------

pub struct Nuclei {
    pub tags: String,
    /// Request per detik (sudah dibatasi 1..500).
    pub rate: String,
    /// Crawl dengan Katana (bila terpasang) lalu cek exposure di direktori yang ditemukan.
    pub crawl: bool,
}

/// Direktori hasil crawl yang ikut dicek Nuclei (tiap direktori = satu putaran template exposure).
const CRAWL_DIRS: usize = 10;
const ETAGS: &str = "dos,fuzz,intrusive,bruteforce,brute-force,default-login";

/// Template yang tumpang tindih dengan engine native -> dibuang supaya tidak dobel.
const NUCLEI_SKIP: &[&str] = &["http-missing-security-headers", "tech-detect"];

impl Scanner for Nuclei {
    fn name(&self) -> &str { "Nuclei" }
    fn scan(&self, target: &str, log: &dyn Fn(&str)) -> Result<Vec<Finding>> {
        // Non-intrusif: tanpa template dos/fuzz/brute-force/default-login, tanpa interactsh (OAST ke server luar).
        let stats = |line: &str| log(&nuclei_stats(line).unwrap_or_else(|| line.into()));
        let out = nuclei(&["-u", target, "-tags", &self.tags, "-etags", ETAGS, "-rl", &self.rate], &stats)?;
        let mut found = parse_nuclei(&String::from_utf8_lossy(&out))?;
        if self.crawl && crate::tools::installed("katana") {
            found.extend(self.crawl_pass(target, log, &stats)?);
        }
        Ok(found)
    }
}

impl Nuclei {
    /// Katana menjelajah situs (kedalaman 2, maks. 60 dtk, host yang sama), lalu template exposure/token
    /// dijalankan di direktori yang ditemukan. Daftar endpoint dicatat sebagai temuan Info (permukaan serangan).
    fn crawl_pass(&self, target: &str, log: &dyn Fn(&str), stats: &dyn Fn(&str)) -> Result<Vec<Finding>> {
        log("Katana: crawl situs (maks. 60 dtk)…");
        let out = crate::sast::run("katana", &work_dir(), &[
            "-u", target, "-d", "2", "-ct", "60s", "-fs", "fqdn", "-jc", "-fsu", "-rl", &self.rate,
            "-ef", "css,png,jpg,jpeg,gif,svg,ico,webp,woff,woff2,ttf,eot,mp4,map", "-silent", "-nc", "-duc",
        ], log)?;
        let urls = crawled(&String::from_utf8_lossy(&out));
        let dirs = crawl_dirs(target, &urls);
        log(&format!("Katana: {} URL, {} direktori dicek", urls.len(), dirs.len()));
        let mut found = vec![];
        if !urls.is_empty() {
            found.push(Finding {
                title: format!("{} endpoint ditemukan crawler", urls.len()),
                location: target.into(),
                description: "Daftar URL yang bisa dijangkau dari halaman publik (link, form, file JavaScript). Ini peta permukaan serangan, bukan celah.".into(),
                impact: "Endpoint yang tidak dimaksudkan publik (admin, debug, API internal) bisa ikut terlihat di sini.".into(),
                recommendation: "Tinjau daftar ini: tutup atau lindungi endpoint yang seharusnya tidak publik.".into(),
                evidence: clip(&urls.iter().take(100).cloned().collect::<Vec<_>>().join("\n")),
                ..finding("Katana", Severity::Info, "crawl-endpoints")
            });
        }
        if !dirs.is_empty() {
            // Daftar target lewat file unik (create_new) di folder sementara.
            let list = work_dir().join(format!("appsec-crawl-{}.txt", uuid::Uuid::new_v4()));
            std::fs::OpenOptions::new().write(true).create_new(true).open(&list)?.write_all(dirs.join("\n").as_bytes())?;
            let r = nuclei(&["-l", list.to_str().unwrap_or_default(), "-tags", "exposure,token", "-etags", ETAGS, "-rl", &self.rate], stats);
            let _ = std::fs::remove_file(&list);
            found.extend(parse_nuclei(&String::from_utf8_lossy(&r?))?);
        }
        Ok(found)
    }
}

/// Folder kerja tool (cwd); tidak ada file dengan nama tetap/tebakan yang dibuat di sana.
fn work_dir() -> std::path::PathBuf {
    // nosemgrep: rust.lang.security.temp-dir.temp-dir
    std::env::temp_dir()
}

fn nuclei(args: &[&str], log: &dyn Fn(&str)) -> Result<Vec<u8>> {
    let mut a = args.to_vec();
    a.extend(["-ni", "-c", "25", "-jsonl", "-silent", "-nc", "-stats", "-si", "15"]);
    crate::sast::run("nuclei", &work_dir(), &a, log)
}

/// URL unik hasil crawl (urutan dipertahankan).
fn crawled(out: &str) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    out.lines().map(str::trim).filter(|l| l.starts_with("http") && seen.insert(l.to_string())).map(String::from).collect()
}

/// Direktori unik (selain root) dari URL crawl, host sama dengan target, maks. CRAWL_DIRS.
fn crawl_dirs(target: &str, urls: &[String]) -> Vec<String> {
    let host = Url::parse(target).ok().and_then(|u| u.host_str().map(String::from));
    let mut seen = std::collections::BTreeSet::new();
    for u in urls.iter().filter_map(|u| Url::parse(u).ok()) {
        if u.host_str().map(String::from) != host {
            continue;
        }
        let path = u.path();
        let dir = &path[..path.rfind('/').unwrap_or(0) + 1];
        if dir.len() > 1 {
            seen.insert(format!("{}{dir}", u.origin().ascii_serialization()));
        }
    }
    seen.into_iter().take(CRAWL_DIRS).collect()
}

/// Baris stats JSON nuclei -> ringkas dan mudah dibaca.
fn nuclei_stats(line: &str) -> Option<String> {
    let v: Value = serde_json::from_str(line).ok()?;
    let g = |k: &str| v[k].as_str().unwrap_or("?").to_string();
    Some(format!("{}% · {}/{} request · {} match · {} error · {}", g("percent"), g("requests"), g("total"), g("matched"), g("errors"), g("duration")))
}

pub fn parse_nuclei(jsonl: &str) -> Result<Vec<Finding>> {
    let mut seen = std::collections::HashSet::new();
    let mut out = vec![];
    for line in jsonl.lines().filter(|l| !l.trim().is_empty()) {
        let v: Value = serde_json::from_str(line)?;
        let (id, at) = (v["template-id"].as_str().unwrap_or_default(), v["matched-at"].as_str().unwrap_or_default());
        let path = Url::parse(at).map(|u| u.path().to_string()).unwrap_or_default();
        if NUCLEI_SKIP.contains(&id) || PROBES.iter().any(|p| p.path != "/" && p.path == path) || !seen.insert((id.to_string(), at.to_string())) {
            continue;
        }
        let i = &v["info"];
        let text = |k: &str| i[k].as_str().unwrap_or_default().trim().to_string();
        let list = |x: &Value| x.as_array().map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join("\n")).unwrap_or_default();
        let sev = match i["severity"].as_str().unwrap_or_default() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Info,
        };
        let refs = list(&i["reference"]);
        let field = |k: &str| v[k].as_str().unwrap_or_default();
        let mut ev = format!("template: {id}\nmatched-at: {at}");
        if !field("matcher-name").is_empty() {
            ev += &format!("\nmatcher: {}", field("matcher-name"));
        }
        let extracted = list(&v["extracted-results"]);
        if !extracted.is_empty() {
            ev += &format!("\nextracted:\n{extracted}");
        }
        if !field("curl-command").is_empty() {
            ev += &format!("\n\nreproduksi:\n{}", field("curl-command"));
        }
        if !field("response").is_empty() {
            ev += &format!("\n\n--- potongan respons ---\n{}", field("response").lines().take(15).collect::<Vec<_>>().join("\n"));
        }
        out.push(Finding {
            title: text("name"),
            location: at.into(),
            description: text("description"),
            impact: list(&i["classification"]["cwe-id"]).to_uppercase(),
            recommendation: match text("remediation") {
                r if !r.is_empty() => r,
                _ if !refs.is_empty() => format!("Referensi:\n{refs}"),
                _ => String::new(),
            },
            evidence: clip(&ev),
            ..finding("Nuclei", sev, id)
        });
    }
    Ok(out)
}

// ---------------- Mozilla HTTP Observatory (opsional, online) ----------------

pub struct Observatory;

impl Scanner for Observatory {
    fn name(&self) -> &str { "Observatory" }
    fn scan(&self, target: &str, _log: &dyn Fn(&str)) -> Result<Vec<Finding>> {
        let (_, host, _) = host_port(target)?;
        if host == "localhost" || host.parse::<IpAddr>().is_ok() {
            bail!("Observatory hanya bisa memindai hostname publik");
        }
        let url = Url::parse_with_params("https://observatory-api.mdn.mozilla.net/api/v2/scan", [("host", &host)])?;
        let v: Value = serde_json::from_str(&client(true)?.post(url).send()?.text()?)?;
        parse_observatory(&v, target)
    }
}

pub fn parse_observatory(v: &Value, target: &str) -> Result<Vec<Finding>> {
    if let Some(e) = v["error"].as_str().or(v["message"].as_str()) {
        bail!("Observatory: {e}");
    }
    let grade = v["grade"].as_str().context("respons Observatory tanpa grade")?;
    let sev = match grade.chars().next() {
        Some('A') => Severity::Info,
        Some('B') => Severity::Low,
        Some('C') => Severity::Medium,
        _ => Severity::High,
    };
    Ok(vec![Finding {
        title: format!("Mozilla Observatory: grade {grade}"),
        location: target.into(),
        description: format!("Skor {} · {} dari {} tes gagal.", v["score"], v["tests_failed"], v["tests_quantity"]),
        impact: "Penilaian pihak ketiga atas header keamanan, cookie, redirect, dan konfigurasi HTTP lain (second opinion untuk modul Headers & TLS).".into(),
        recommendation: format!("Lihat rincian tiap tes: {}", v["details_url"].as_str().unwrap_or("https://developer.mozilla.org/en-US/observatory")),
        evidence: format!("POST https://observatory-api.mdn.mozilla.net/api/v2/scan?host=…\ngrade: {grade} · score: {} · lulus: {} · gagal: {} · total: {}\ndipindai: {}\ndetail: {}",
            v["score"], v["tests_passed"], v["tests_failed"], v["tests_quantity"], v["scanned_at"].as_str().unwrap_or("-"), v["details_url"].as_str().unwrap_or("-")),
        ..finding("Observatory", sev, "observatory")
    }])
}

// ---------------- testssl.sh (TLS mendalam) ----------------

pub struct Testssl;

impl Scanner for Testssl {
    fn name(&self) -> &str { "testssl" }
    fn scan(&self, target: &str, log: &dyn Fn(&str)) -> Result<Vec<Finding>> {
        let url = Url::parse(target)?;
        if url.scheme() != "https" {
            log("lewati: target bukan HTTPS");
            return Ok(vec![]);
        }
        let script = crate::tools::testssl().context("testssl.sh belum terpasang (Pengaturan → testssl.sh → Pasang)")?;
        let host = format!("{}:{}", url.host_str().context("host kosong")?, url.port_or_known_default().unwrap_or(443));
        // File JSON unik; testssl menolak menimpa file yang sudah ada.
        let json = work_dir().join(format!("appsec-testssl-{}.json", uuid::Uuid::new_v4()));
        let json_s = json.to_str().unwrap_or_default().to_string();
        let r = crate::sast::run_path("testssl", Path::new("bash"), &work_dir(), &[
            script.to_str().unwrap_or_default(), "--quiet", "--color", "0", "--warnings", "off", "--sneaky",
            "--severity", "LOW", "-p", "-s", "-S", "-U", "--jsonfile", &json_s, &host,
        ], log);
        let data = std::fs::read(&json);
        let _ = std::fs::remove_file(&json);
        // testssl keluar dengan kode != 0 bila ada temuan; yang penting JSON-nya ada.
        let data = data.map_err(|e| anyhow::anyhow!("testssl tidak menghasilkan laporan ({e}){}", r.err().map(|e| format!(": {e:#}")).unwrap_or_default()))?;
        parse_testssl(&serde_json::from_slice(&data)?, &host)
    }
}

pub fn parse_testssl(v: &Value, host: &str) -> Result<Vec<Finding>> {
    let mut out = vec![];
    for x in v.as_array().context("output testssl bukan array")? {
        let g = |k: &str| x[k].as_str().unwrap_or_default();
        let sev = match g("severity") {
            "CRITICAL" => Severity::Critical,
            "HIGH" => Severity::High,
            "MEDIUM" => Severity::Medium,
            "LOW" => Severity::Low,
            _ => continue,
        };
        let (id, text) = (g("id"), g("finding"));
        let mut ev = format!("cek: {id}\nhasil: {text}");
        for k in ["cve", "cwe"] {
            if !g(k).is_empty() {
                ev += &format!("\n{k}: {}", g(k));
            }
        }
        out.push(Finding {
            title: format!("TLS: {id}{}", if text.is_empty() || text == "--" { String::new() } else { format!(" — {}", text.chars().take(80).collect::<String>()) }),
            location: host.into(),
            description: format!("testssl.sh menandai pengecekan {id} sebagai {}: {text}", g("severity")),
            impact: if g("cve").is_empty() { "Konfigurasi TLS yang lemah memudahkan penyadapan atau pemalsuan koneksi.".into() } else { format!("Rentan terhadap {} pada lapisan TLS.", g("cve")) },
            recommendation: "Perbarui konfigurasi TLS server mengikuti Mozilla SSL Configuration Generator (https://ssl-config.mozilla.org): matikan protokol/cipher lama dan perbarui library TLS.".into(),
            evidence: ev,
            ..finding("testssl", sev, &format!("testssl-{id}"))
        });
    }
    Ok(out)
}

// ---------------- nmap (port + versi layanan) ----------------

pub struct Nmap;

/// Port berisiko (tabel Ports) + port umum yang berguna untuk inventaris versi layanan.
const NMAP_EXTRA: &[u16] = &[22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3000, 5000, 8000, 8080, 8443, 8888, 9090];

impl Scanner for Nmap {
    fn name(&self) -> &str { "Nmap" }
    fn scan(&self, target: &str, log: &dyn Fn(&str)) -> Result<Vec<Finding>> {
        let (_, host, _) = host_port(target)?;
        anyhow::ensure!(crate::tools::installed("nmap"), "nmap tidak ditemukan di sistem; pasang dulu (mis. `sudo apt install nmap` / `brew install nmap`)");
        let canary = [47_123u16, 61_987].into_iter().find(|&p| connect(&host, p, Duration::from_secs(3)).is_ok());
        if let Some(p) = canary {
            log(&format!("port kanari {p} ikut tersambung: hanya port dengan layanan teridentifikasi yang dilaporkan"));
        }
        let ports = PORTS.iter().map(|p| p.0).chain(NMAP_EXTRA.iter().copied()).map(|p| p.to_string()).collect::<Vec<_>>().join(",");
        // -sT: TCP connect (tanpa root), -sV ringan, timing normal agar tidak membanjiri target.
        let out = crate::sast::run("nmap", &work_dir(), &["-sT", "-sV", "--version-light", "-Pn", "-T3", "-p", &ports, "-oG", "-", &host], log)?;
        Ok(parse_nmap(&String::from_utf8_lossy(&out), &host, canary.is_some()))
    }
}

pub fn parse_nmap(grepable: &str, host: &str, accept_all: bool) -> Vec<Finding> {
    let mut open = vec![];
    for line in grepable.lines().filter(|l| l.starts_with("Host:")) {
        let Some(ports) = line.split('\t').find_map(|f| f.strip_prefix("Ports: ")) else { continue };
        for entry in ports.split(", ") {
            let f: Vec<&str> = entry.split('/').collect();
            if f.len() < 7 || f[1] != "open" {
                continue;
            }
            let (port, svc, ver) = (f[0].parse::<u16>().unwrap_or_default(), f[4], f[6..].join("/").trim().trim_end_matches('/').to_string());
            // Host "terima semua port": tanpa identifikasi layanan berarti tidak terbukti terbuka.
            if accept_all && (svc.is_empty() || svc == "tcpwrapped" || svc.ends_with('?')) {
                continue;
            }
            open.push((port, svc.to_string(), ver));
        }
    }
    let mut out = vec![];
    for (port, svc, ver) in &open {
        let Some(&(_, name, sev)) = PORTS.iter().find(|p| p.0 == *port) else { continue };
        out.push(Finding {
            title: format!("Port {port} ({name}) terbuka ke publik"),
            location: format!("{host}:{port}"),
            description: format!("nmap mendeteksi layanan {}{} di port {port}.", if svc.is_empty() { "?" } else { svc }, if ver.is_empty() { String::new() } else { format!(" ({ver})") }),
            impact: format!("{name} bisa dijangkau langsung dari internet. Layanan ini seharusnya hanya di jaringan internal."),
            recommendation: format!("Tutup port {port} di firewall / security group, bind layanan ke 127.0.0.1 atau jaringan privat, dan akses lewat VPN / SSH tunnel. Pastikan versinya terbaru."),
            evidence: format!("nmap -sT -sV {host} -p {port}\n{port}/tcp open {svc} {ver}"),
            ..finding("Nmap", sev, &format!("port-{port}"))
        });
    }
    if !open.is_empty() {
        out.push(Finding {
            title: format!("{} port terbuka dengan versi layanan", open.len()),
            location: host.into(),
            description: "Inventaris layanan yang menjawab dari luar beserta versinya (deteksi versi nmap).".into(),
            impact: "Versi layanan yang terlihat memudahkan penyerang mencocokkan CVE yang berlaku.".into(),
            recommendation: "Tutup port yang tidak perlu publik, perbarui layanan ke versi terbaru, dan sembunyikan banner versi bila memungkinkan.".into(),
            evidence: open.iter().map(|(p, s, v)| format!("{p}/tcp  {s}  {v}")).collect::<Vec<_>>().join("\n"),
            ..finding("Nmap", Severity::Info, "nmap-services")
        });
    }
    out
}

// ---------------- OWASP ZAP ----------------

/// `active: false` = baseline (spider + passive scan, tidak menyerang). `true` = juga active scan (intrusif).
pub struct Zap {
    pub active: bool,
}

impl Scanner for Zap {
    fn name(&self) -> &str { if self.active { "ZAP-active" } else { "ZAP" } }
    fn scan(&self, target: &str, log: &dyn Fn(&str)) -> Result<Vec<Finding>> {
        let zap = crate::tools::zap().context("ZAP belum terpasang (Pengaturan → OWASP ZAP → Pasang)")?;
        let url = Url::parse(target)?;
        // Folder kerja unik: plan + laporan, dihapus setelah selesai.
        let work = work_dir().join(format!("appsec-zap-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&work)?;
        let r = (|| {
            let scope = format!("{}.*", regex_escape(&url.origin().ascii_serialization()));
            let active = if self.active {
                "- type: activeScan\n  parameters:\n    maxScanDurationInMins: 15\n    maxRuleDurationInMins: 2\n"
            } else { "" };
            let plan = format!(r#"env:
  contexts:
  - name: appsec
    urls: ['{target}']
    includePaths: ['{scope}']
  parameters:
    failOnError: false
    progressToStdout: true
jobs:
- type: passiveScan-config
  parameters:
    maxAlertsPerRule: 10
- type: spider
  parameters:
    maxDuration: 3
    maxDepth: 5
    maxChildren: 50
- type: passiveScan-wait
  parameters:
    maxDuration: 5
{active}- type: report
  parameters:
    template: traditional-json
    reportDir: '{dir}'
    reportFile: zap-report
"#, dir = work.display());
            std::fs::write(work.join("plan.yaml"), plan)?;
            // Home per-run di dalam folder kerja: tanpa lock bentrok antar scan ZAP (baseline + active) atau sisa lock.
            let home = work.join("home");
            std::fs::create_dir_all(&home)?;
            let (zap_s, plan_s, home_s) = (zap.to_string_lossy().to_string(), work.join("plan.yaml").to_string_lossy().to_string(), home.to_string_lossy().to_string());
            let java = crate::tools::java_home().map(|h| format!("JAVA_HOME={}", h.display()));
            let path = crate::tools::java_home().map(|h| format!("PATH={}:{}", h.join("bin").display(), std::env::var("PATH").unwrap_or_default()));
            let mut args: Vec<&str> = java.iter().chain(path.iter()).map(String::as_str).collect();
            // Port proxy bebas (default 8080 sering terpakai).
            let port = std::net::TcpListener::bind("127.0.0.1:0")?.local_addr()?.port().to_string();
            args.extend(["bash", &zap_s, "-cmd", "-port", &port, "-dir", &home_s, "-autorun", &plan_s, "-silent", "-notel"]);
            log(if self.active { "ZAP: spider + passive + active scan (maks. ±25 menit)…" } else { "ZAP: spider + passive scan (maks. ±8 menit)…" });
            crate::sast::run_path("ZAP", Path::new("env"), &work, &args, log)?;
            let report = std::fs::read_dir(&work)?.flatten().map(|e| e.path())
                .find(|p| p.extension().is_some_and(|e| e == "json")).context("ZAP tidak menghasilkan laporan")?;
            parse_zap(&serde_json::from_slice(&std::fs::read(report)?)?, self.name())
        })();
        let _ = std::fs::remove_dir_all(&work);
        r
    }
}

fn regex_escape(s: &str) -> String {
    s.chars().map(|c| if "\\.+*?()|[]{}^$".contains(c) { format!("\\{c}") } else { c.to_string() }).collect()
}

/// Teks deskripsi ZAP berisi tag HTML sederhana (<p>, <br>).
fn strip_html(s: &str) -> String {
    let mut out = String::new();
    let mut tag = false;
    for c in s.chars() {
        match c {
            '<' => { tag = true; out.push('\n') }
            '>' => tag = false,
            _ if !tag => out.push(c),
            _ => {}
        }
    }
    out.lines().map(str::trim).filter(|l| !l.is_empty()).collect::<Vec<_>>().join("\n")
}

pub fn parse_zap(v: &Value, tool: &str) -> Result<Vec<Finding>> {
    let mut out = vec![];
    for site in v["site"].as_array().into_iter().flatten() {
        for a in site["alerts"].as_array().into_iter().flatten() {
            let g = |k: &str| a[k].as_str().unwrap_or_default();
            let sev = match g("riskcode") { "3" => Severity::High, "2" => Severity::Medium, "1" => Severity::Low, _ => Severity::Info };
            let inst = a["instances"].as_array().cloned().unwrap_or_default();
            let first = inst.first().cloned().unwrap_or_default();
            let fi = |k: &str| first[k].as_str().unwrap_or_default().to_string();
            let mut ev = inst.iter().take(5).map(|i| {
                let f = |k: &str| i[k].as_str().unwrap_or_default();
                let mut l = format!("{} {}", f("method"), f("uri"));
                for k in ["param", "attack", "evidence"] {
                    if !f(k).is_empty() { l += &format!("\n  {k}: {}", f(k)) }
                }
                l
            }).collect::<Vec<_>>().join("\n");
            if inst.len() > 5 {
                ev += &format!("\n… dan {} lokasi lain", inst.len() - 5);
            }
            let cwe = g("cweid");
            out.push(Finding {
                title: g("alert").into(),
                location: fi("uri"),
                description: strip_html(g("desc")),
                impact: format!("{}{}", g("riskdesc"), if cwe.is_empty() || cwe == "-1" || cwe == "0" { String::new() } else { format!(" · CWE-{cwe}") }),
                recommendation: [strip_html(g("solution")), strip_html(g("reference"))].into_iter().filter(|x| !x.is_empty()).collect::<Vec<_>>().join("\n\nReferensi:\n"),
                evidence: clip(&ev),
                ..finding(tool, sev, &format!("zap-{}", g("pluginid")))
            });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #[test]
    fn crawl_dirs_keep_port_and_skip_other_hosts() {
        let urls: Vec<String> = ["http://localhost:5173/src/a.ts", "http://localhost:5173/src/b.ts", "http://localhost:5173/",
            "http://localhost:5173/api/v1/x?id=1", "https://cdn.example.com/lib/x.js"].map(String::from).into();
        assert_eq!(crawl_dirs("http://localhost:5173", &urls), vec!["http://localhost:5173/api/v1/", "http://localhost:5173/src/"]);
    }

    use super::*;

    #[test]
    fn content_checks_avoid_soft_404() {
        assert!(env_like("APP_KEY=base64:x\nDB_PASSWORD=secret\n"));
        assert!(!env_like("<html><body>APP=1\nB=2</body></html>"));
        assert!(sql_dump("-- dump\nCREATE TABLE users (id int);"));
        assert!(!sql_dump("<html>Not found</html>"));
        assert!(debug_page("Traceback (most recent call last):"));
        assert!(!debug_page("<h1>404 Not Found</h1>"));
    }

    #[test]
    fn optional_modules_parse() {
        let jsonl = r#"{"template-id":"laravel-env","matched-at":"http://h/.env","info":{"name":"x","severity":"high"}}
{"template-id":"exposed-panel","matched-at":"http://h/admin","info":{"name":"Admin panel","severity":"medium","reference":["https://r"],"classification":{"cwe-id":["cwe-200"]}}}
{"template-id":"exposed-panel","matched-at":"http://h/admin","info":{"name":"Admin panel","severity":"medium"}}
{"template-id":"http-missing-security-headers","matched-at":"http://h","info":{"name":"x","severity":"info"}}"#;
        let n = parse_nuclei(jsonl).unwrap();
        assert_eq!(n.len(), 1); // .env sudah dicakup Files, duplikat & header dibuang
        assert_eq!((n[0].severity, n[0].impact.as_str(), n[0].recommendation.as_str()), (Severity::Medium, "CWE-200", "Referensi:\nhttps://r"));

        let o = parse_observatory(&serde_json::json!({"grade": "C+", "score": 50, "tests_failed": 4, "tests_quantity": 10, "details_url": "https://d", "error": null}), "https://h").unwrap();
        assert_eq!((o[0].severity, o[0].title.as_str()), (Severity::Medium, "Mozilla Observatory: grade C+"));
        assert!(parse_observatory(&serde_json::json!({"error": "invalid-hostname", "message": "x"}), "https://h").is_err());
    }
}
