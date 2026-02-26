pub fn multi_monitor() -> libafl::monitors::MultiMonitor<fn(&str)> {
    libafl::monitors::MultiMonitor::new(print_status as fn(&str))
}

fn print_status(s: &str) {
    println!("{s}");
}
