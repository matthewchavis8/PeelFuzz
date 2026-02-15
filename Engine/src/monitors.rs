/// Monitor creation and dispatch.
use libafl::monitors::SimpleMonitor;

/// Create a `SimpleMonitor` with console output.
pub fn simple_monitor() -> SimpleMonitor<fn(&str)> {
    SimpleMonitor::new(print_status as fn(&str))
}

/// Create a `MultiMonitor` for multi-core fuzzing (implements Clone).
#[cfg(feature = "fork")]
pub fn multi_monitor() -> libafl::monitors::MultiMonitor<fn(&str)> {
    libafl::monitors::MultiMonitor::new(print_status as fn(&str))
}

fn print_status(s: &str) {
    println!("{s}");
}
