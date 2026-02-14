/// Monitor creation and dispatch.
use std::time::Instant;

use libafl::monitors::SimpleMonitor;

/// Create a `SimpleMonitor` that throttles output to at most once per second.
pub fn throttled_simple_monitor() -> SimpleMonitor<impl FnMut(&str)> {
    let mut last_print = Instant::now();
    SimpleMonitor::new(move |s| {
        println!("{s}");
    })
}

/// Create a `TuiMonitor` (requires `tui` feature).
#[cfg(feature = "tui")]
pub fn tui_monitor() -> libafl::monitors::TuiMonitor {
    libafl::monitors::TuiMonitor::builder()
        .title("PeelFuzz")
        .version(env!("CARGO_PKG_VERSION"))
        .enhanced_graphics(true)
        .build()
}
