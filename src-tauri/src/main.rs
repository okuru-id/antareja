// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
  // WebKitGTK + Wayland/NVIDIA sering menampilkan jendela kosong/beku dengan renderer DMABUF.
  #[cfg(target_os = "linux")]
  if std::env::var_os("WEBKIT_DISABLE_DMABUF_RENDERER").is_none() {
    // Aman: dipanggil di awal main sebelum ada thread lain.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1") };
  }
  app_lib::run();
}
