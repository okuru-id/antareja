//! Pembatalan scan: token dipasang per thread scanner, dibaca oleh `sast::run_path` untuk mematikan tool.
use std::cell::RefCell;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

pub type Token = Arc<AtomicBool>;

thread_local!(static TOKEN: RefCell<Option<Token>> = const { RefCell::new(None) });

pub(crate) fn set(t: Option<Token>) {
    TOKEN.with(|c| *c.borrow_mut() = t)
}

pub(crate) fn current() -> Option<Token> {
    TOKEN.with(|c| c.borrow().clone())
}

pub fn is_cancelled(t: &Token) -> bool {
    t.load(Ordering::Relaxed)
}
