//! Opt-in diagnostics. No source paths or event payloads are logged.
use std::{sync::OnceLock, time::Instant};

pub(crate) struct PhaseTimer {
    phase: &'static str,
    started: Instant,
}

pub(crate) fn phase(name: &'static str) -> Option<PhaseTimer> {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    ENABLED
        .get_or_init(|| std::env::var_os("QTRACE_UI_OPEN_PROFILE").is_some())
        .then(|| PhaseTimer {
            phase: name,
            started: Instant::now(),
        })
}

impl Drop for PhaseTimer {
    fn drop(&mut self) {
        eprintln!(
            "qtrace_open_phase {{\"phase\":\"{}\",\"seconds\":{:.9}}}",
            self.phase,
            self.started.elapsed().as_secs_f64()
        );
    }
}
