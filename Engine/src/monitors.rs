#[cfg(feature = "std")]
pub fn multi_monitor() -> libafl::monitors::MultiMonitor<fn(&str)> {
    libafl::monitors::MultiMonitor::new(print_status as fn(&str))
}

#[cfg(feature = "std")]
fn print_status(s: &str) {
    println!("{s}");
}

/// Returns a `SimpleMonitor` with a no-op callback for no_std builds.
///
/// By default this discards all status output since there is no stdout on
/// baremetal. To see fuzzer stats on your hardware, replace the closure
/// with your platform's print function — for example, write to a UART
/// peripheral, SWO trace port, or semihosting channel:
///
/// ```ignore
/// SimpleMonitor::new(|s| my_uart_write(s))
/// ```
#[cfg(not(feature = "std"))]
pub fn simple_monitor() -> libafl::monitors::SimpleMonitor<fn(&str)> {
    libafl::monitors::SimpleMonitor::new(noop_print as fn(&str))
}

#[cfg(not(feature = "std"))]
fn noop_print(_s: &str) {}
