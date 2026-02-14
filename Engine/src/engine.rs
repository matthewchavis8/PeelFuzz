/// PeelFuzzer builder — composable, ergonomic fuzzer configuration.
use std::time::Duration;

use libafl::executors::ExitKind;
use libafl::inputs::BytesInput;

use crate::config::SchedulerType;

/// Builder for configuring and running a PeelFuzz fuzzing session.
///
/// # Example
/// ```rust,no_run
/// unsafe {
///     PeelFuzzer::new(my_harness)
///         .scheduler(SchedulerType::Weighted)
///         .timeout(Duration::from_secs(2))
///         .crash_dir("./my_crashes")
///         .seed_count(16)
///         .use_tui()
///         .run();
/// }
/// ```
pub struct PeelFuzzer<H>
where
    H: FnMut(&BytesInput) -> ExitKind,
{
    harness: H,
    scheduler_type: SchedulerType,
    timeout: Duration,
    crash_dir: String,
    seed_count: usize,
    tui: bool,
}

impl<H> PeelFuzzer<H>
where
    H: FnMut(&BytesInput) -> ExitKind,
{
    /// Create a new fuzzer with the given harness and sensible defaults.
    pub fn new(harness: H) -> Self {
        Self {
            harness,
            scheduler_type: SchedulerType::Queue,
            timeout: Duration::from_secs(1),
            crash_dir: "./crashes".to_string(),
            seed_count: 8,
            tui: false,
        }
    }

    /// Select the scheduler strategy.
    pub fn scheduler(mut self, scheduler_type: SchedulerType) -> Self {
        self.scheduler_type = scheduler_type;
        self
    }

    /// Set the executor timeout per input.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the directory for crash outputs.
    pub fn crash_dir(mut self, dir: &str) -> Self {
        self.crash_dir = dir.to_string();
        self
    }

    /// Set the number of initial seed inputs.
    pub fn seed_count(mut self, count: usize) -> Self {
        self.seed_count = count;
        self
    }

    /// Enable the TUI monitor (requires `tui` feature).
    pub fn use_tui(mut self) -> Self {
        self.tui = true;
        self
    }

    /// Run the fuzzer. This consumes the builder and starts the fuzz loop.
    ///
    /// # Safety
    /// The harness must be safe to call with arbitrary byte inputs.
    /// Coverage instrumentation pointers must be valid.
    pub unsafe fn run(self) {
        let PeelFuzzer {
            mut harness,
            scheduler_type,
            timeout,
            crash_dir,
            seed_count,
            tui,
        } = self;

        match (scheduler_type, tui) {
            (SchedulerType::Queue, false) => {
                let mon = crate::monitors::throttled_simple_monitor();
                run_engine!(harness, mon, crash_dir, seed_count, timeout, |_s, _o| {
                    libafl::schedulers::QueueScheduler::new()
                });
            }
            (SchedulerType::Weighted, false) => {
                let mon = crate::monitors::throttled_simple_monitor();
                run_engine!(
                    harness,
                    mon,
                    crash_dir,
                    seed_count,
                    timeout,
                    |state, observer| crate::schedulers::StdWeightedScheduler::new(
                        &mut state, &observer
                    )
                );
            }
            #[cfg(feature = "tui")]
            (SchedulerType::Queue, true) => {
                let mon = crate::monitors::tui_monitor();
                run_engine!(harness, mon, crash_dir, seed_count, timeout, |_s, _o| {
                    libafl::schedulers::QueueScheduler::new()
                });
            }
            #[cfg(feature = "tui")]
            (SchedulerType::Weighted, true) => {
                let mon = crate::monitors::tui_monitor();
                run_engine!(
                    harness,
                    mon,
                    crash_dir,
                    seed_count,
                    timeout,
                    |state, observer| crate::schedulers::StdWeightedScheduler::new(
                        &mut state, &observer
                    )
                );
            }
            #[cfg(not(feature = "tui"))]
            (_, true) => {
                eprintln!("TUI requested but `tui` feature not compiled. Falling back to console.");
                let mon = crate::monitors::throttled_simple_monitor();
                match scheduler_type {
                    SchedulerType::Queue => {
                        run_engine!(harness, mon, crash_dir, seed_count, timeout, |_s, _o| {
                            libafl::schedulers::QueueScheduler::new()
                        });
                    }
                    SchedulerType::Weighted => {
                        run_engine!(
                            harness,
                            mon,
                            crash_dir,
                            seed_count,
                            timeout,
                            |state, observer| crate::schedulers::StdWeightedScheduler::new(
                                &mut state, &observer
                            )
                        );
                    }
                }
            }
        }
    }
}

/// Internal macro that stamps out the full fuzzer body, parameterized by a
/// scheduler-construction expression that receives `|state, observer|`.
macro_rules! run_engine {
    ($harness:expr, $monitor:expr, $crash_dir:expr, $seed_count:expr, $timeout:expr,
     |$state:ident, $observer:ident| $make_scheduler:expr) => {{
        use core::num::NonZero;
        use std::path::PathBuf;

        use libafl::{
            corpus::{Corpus, InMemoryCorpus, OnDiskCorpus},
            events::SimpleEventManager,
            feedbacks::{CrashFeedback, MaxMapFeedback},
            fuzzer::{Fuzzer, StdFuzzer},
            generators::RandBytesGenerator,
            mutators::{havoc_mutations::havoc_mutations, scheduled::HavocScheduledMutator},
            observers::StdMapObserver,
            stages::mutational::StdMutationalStage,
            state::{HasCorpus, StdState},
        };
        use libafl_bolts::{current_nanos, rands::StdRand, tuples::tuple_list};

        use crate::sanitizer_coverage::{MAP_SIZE, SIGNALS_PTR};

        unsafe {
            if SIGNALS_PTR.is_null() {
                crate::sanitizer_coverage::init_coverage();
            }

            let $observer = StdMapObserver::from_mut_ptr("signals", SIGNALS_PTR, MAP_SIZE);
            let mut feedback = MaxMapFeedback::new(&$observer);
            let mut objective = CrashFeedback::new();

            let mut $state = StdState::new(
                StdRand::with_seed(current_nanos()),
                InMemoryCorpus::new(),
                OnDiskCorpus::new(PathBuf::from($crash_dir)).unwrap(),
                &mut feedback,
                &mut objective,
            )
            .unwrap();

            let mut mgr = SimpleEventManager::new($monitor);
            let scheduler = $make_scheduler;
            let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

            let mut executor = libafl::executors::inprocess::InProcessExecutor::with_timeout(
                &mut $harness,
                tuple_list!($observer),
                &mut fuzzer,
                &mut $state,
                &mut mgr,
                $timeout,
            )
            .unwrap();

            if $state.corpus().count() == 0 {
                let mut generator = RandBytesGenerator::new(NonZero::new(32).unwrap());
                $state
                    .generate_initial_inputs(
                        &mut fuzzer,
                        &mut executor,
                        &mut generator,
                        &mut mgr,
                        $seed_count,
                    )
                    .unwrap();
            }

            let mutator = HavocScheduledMutator::new(havoc_mutations());
            let mut stages = tuple_list!(StdMutationalStage::new(mutator));

            fuzzer
                .fuzz_loop(&mut stages, &mut executor, &mut $state, &mut mgr)
                .unwrap();
        }
    }};
}

use run_engine;
