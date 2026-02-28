use crate::config::SchedulerType;
use core::time::Duration;
use libafl::executors::ExitKind;
use libafl::inputs::BytesInput;

#[cfg(not(feature = "std"))]
use alloc::string::String;

/// Builder for configuring and running a PeelFuzz fuzzing session.
pub struct PeelFuzzer<H>
where
    H: FnMut(&BytesInput) -> ExitKind,
{
    harness: H,
    scheduler_type: SchedulerType,
    timeout: Duration,
    fuzz_duration: Duration,
    crash_dir: String,
    seed_count: usize,
    core_count: usize,
}

impl<H> PeelFuzzer<H>
where
    H: FnMut(&BytesInput) -> ExitKind,
{
    /// Create a new fuzzer with the given harness and sensible defaults.
    pub fn new(harness: H) -> Self {
        let core_count = {
            #[cfg(feature = "std")]
            {
                std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(1)
            }
            #[cfg(not(feature = "std"))]
            {
                1
            }
        };

        Self {
            harness,
            scheduler_type: SchedulerType::Queue,
            timeout: Duration::from_secs(1),
            fuzz_duration: Duration::from_secs(300),
            crash_dir: "./crashes".into(),
            seed_count: 8,
            core_count,
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
        self.crash_dir = dir.into();
        self
    }

    /// Set the number of initial seed inputs.
    pub fn seed_count(mut self, count: usize) -> Self {
        self.seed_count = count;
        self
    }

    /// Set the total duration for the fuzzing session.
    pub fn fuzz_duration(mut self, dur: Duration) -> Self {
        self.fuzz_duration = dur;
        self
    }

    /// Set the number of cores for parallel fuzzing.
    pub fn core_count(mut self, count: usize) -> Self {
        self.core_count = count;
        self
    }

    /// Run the fuzzer (std build — multicore, fork-based).
    #[cfg(feature = "std")]
    pub unsafe fn run(self) {
        let PeelFuzzer {
            mut harness,
            scheduler_type,
            timeout,
            fuzz_duration,
            crash_dir,
            seed_count,
            core_count,
        } = self;

        let mon = crate::monitors::multi_monitor();
        match scheduler_type {
            SchedulerType::Queue => {
                run_engine_multicore!(
                    harness,
                    mon,
                    crash_dir,
                    seed_count,
                    timeout,
                    core_count,
                    fuzz_duration,
                    |_s, _o| { libafl::schedulers::QueueScheduler::new() }
                );
            }
            SchedulerType::Weighted => {
                run_engine_multicore!(
                    harness,
                    mon,
                    crash_dir,
                    seed_count,
                    timeout,
                    core_count,
                    fuzz_duration,
                    |state, observer| crate::schedulers::StdWeightedScheduler::new(
                        &mut state, &observer
                    )
                );
            }
        }
    }

    /// Run the fuzzer (no_std build — single-core, in-memory only).
    #[cfg(not(feature = "std"))]
    pub unsafe fn run(self) {
        let PeelFuzzer {
            mut harness,
            scheduler_type,
            seed_count,
            ..
        } = self;

        let mon = crate::monitors::simple_monitor();
        match scheduler_type {
            SchedulerType::Queue => {
                run_engine_singlecore!(harness, mon, seed_count, |_s, _o| {
                    libafl::schedulers::QueueScheduler::new()
                });
            }
            SchedulerType::Weighted => {
                run_engine_singlecore!(harness, mon, seed_count, |state, observer| {
                    crate::schedulers::StdWeightedScheduler::new(&mut state, &observer)
                });
            }
        }
    }
}

// ---------------------------------------------------------------------------
// std: Multicore macro using LibAFL Launcher with fork-based parallelism.
// ---------------------------------------------------------------------------
#[cfg(feature = "std")]
macro_rules! run_engine_multicore {
    ($harness:expr, $monitor:expr, $crash_dir:expr, $seed_count:expr, $timeout:expr, $core_count:expr, $fuzz_duration:expr,
     |$state:ident, $observer:ident| $make_scheduler:expr) => {{
        use core::num::NonZero;
        use std::path::PathBuf;

        use libafl::{
            corpus::{Corpus, InMemoryCorpus, OnDiskCorpus},
            events::{EventConfig, launcher::Launcher},
            feedbacks::{
                CrashFeedback, EagerOrFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback,
            },
            fuzzer::{Fuzzer, StdFuzzer},
            generators::RandBytesGenerator,
            mutators::{havoc_mutations::havoc_mutations, scheduled::HavocScheduledMutator},
            observers::{StdMapObserver, TimeObserver},
            stages::mutational::StdMutationalStage,
            state::{HasCorpus, StdState},
        };
        use libafl_bolts::{
            core_affinity::Cores,
            current_nanos,
            rands::StdRand,
            shmem::{ShMemProvider, StdShMemProvider},
            tuples::tuple_list,
        };

        use crate::sanitizer_coverage::{MAP_SIZE, SIGNALS_PTR};

        let cores_str = format!("0-{}", $core_count - 1);
        let cores = Cores::from_cmdline(&cores_str).unwrap();
        let shmem_provider = StdShMemProvider::new().unwrap();

        let crash_dir = $crash_dir.clone();
        let seed_count = $seed_count;
        let timeout = $timeout;
        let fuzz_duration = $fuzz_duration;

        let mut launcher = Launcher::builder()
            .shmem_provider(shmem_provider)
            .monitor($monitor)
            .configuration(EventConfig::AlwaysUnique)
            .cores(&cores)
            .run_client(move |_state_opt, mut mgr, _client_desc| {
                unsafe {
                    if SIGNALS_PTR.is_null() {
                        crate::sanitizer_coverage::init_coverage();
                    }

                    let $observer = StdMapObserver::from_mut_ptr("signals", SIGNALS_PTR, MAP_SIZE);
                    let time_observer = TimeObserver::new("time");

                    let mut feedback = EagerOrFeedback::new(
                        MaxMapFeedback::new(&$observer),
                        TimeFeedback::new(&time_observer),
                    );
                    let mut objective =
                        EagerOrFeedback::new(CrashFeedback::new(), TimeoutFeedback::new());

                    let mut $state = StdState::new(
                        StdRand::with_seed(current_nanos()),
                        InMemoryCorpus::new(),
                        OnDiskCorpus::new(PathBuf::from(crash_dir.clone())).unwrap(),
                        &mut feedback,
                        &mut objective,
                    )
                    .unwrap();

                    let scheduler = $make_scheduler;
                    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

                    let mut executor =
                        libafl::executors::inprocess::InProcessExecutor::with_timeout(
                            &mut $harness,
                            tuple_list!($observer, time_observer),
                            &mut fuzzer,
                            &mut $state,
                            &mut mgr,
                            timeout,
                        )
                        .unwrap();

                    if $state.corpus().count() == 0 {
                        let seed_sizes: [usize; 5] = [4, 16, 32, 64, 128];
                        let seeds_per_size = seed_count / seed_sizes.len();
                        let remainder = seed_count % seed_sizes.len();

                        for (i, &size) in seed_sizes.iter().enumerate() {
                            let count = seeds_per_size + if i < remainder { 1 } else { 0 };
                            if count > 0 {
                                let mut generator =
                                    RandBytesGenerator::new(NonZero::new(size).unwrap());
                                $state
                                    .generate_initial_inputs(
                                        &mut fuzzer,
                                        &mut executor,
                                        &mut generator,
                                        &mut mgr,
                                        count,
                                    )
                                    .unwrap();
                            }
                        }
                    }

                    let mutator = HavocScheduledMutator::new(havoc_mutations());
                    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

                    let deadline = std::time::Instant::now() + fuzz_duration;
                    loop {
                        if std::time::Instant::now() >= deadline {
                            break;
                        }
                        let _ = fuzzer.fuzz_one(&mut stages, &mut executor, &mut $state, &mut mgr);
                    }
                }

                Ok(())
            })
            .build();

        launcher
            .launch::<BytesInput, StdState<
                InMemoryCorpus<BytesInput>,
                BytesInput,
                libafl_bolts::rands::StdRand,
                OnDiskCorpus<BytesInput>,
            >>()
            .expect("Failed to launch multicore fuzzer");
    }};
}

#[cfg(feature = "std")]
use run_engine_multicore;

// ---------------------------------------------------------------------------
// no_std: Single-core macro — no fork, no filesystem, no clock.
// ---------------------------------------------------------------------------
#[cfg(not(feature = "std"))]
macro_rules! run_engine_singlecore {
    ($harness:expr, $monitor:expr, $seed_count:expr,
     |$state:ident, $observer:ident| $make_scheduler:expr) => {{
        use core::num::NonZero;

        use libafl::{
            corpus::{Corpus, InMemoryCorpus},
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

        let seed_count = $seed_count;

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
                InMemoryCorpus::new(), // solutions stored in RAM (no filesystem)
                &mut feedback,
                &mut objective,
            )
            .unwrap();

            let scheduler = $make_scheduler;
            let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

            let mut mgr = SimpleEventManager::new($monitor);

            let mut executor = libafl::executors::inprocess::InProcessExecutor::new(
                &mut $harness,
                tuple_list!($observer),
                &mut fuzzer,
                &mut $state,
                &mut mgr,
            )
            .unwrap();

            if $state.corpus().count() == 0 {
                let seed_sizes: [usize; 5] = [4, 16, 32, 64, 128];
                let seeds_per_size = seed_count / seed_sizes.len();
                let remainder = seed_count % seed_sizes.len();

                for (i, &size) in seed_sizes.iter().enumerate() {
                    let count = seeds_per_size + if i < remainder { 1 } else { 0 };
                    if count > 0 {
                        let mut generator = RandBytesGenerator::new(NonZero::new(size).unwrap());
                        $state
                            .generate_initial_inputs(
                                &mut fuzzer,
                                &mut executor,
                                &mut generator,
                                &mut mgr,
                                count,
                            )
                            .unwrap();
                    }
                }
            }

            let mutator = HavocScheduledMutator::new(havoc_mutations());
            let mut stages = tuple_list!(StdMutationalStage::new(mutator));

            // Runs forever — the host / debugger / watchdog terminates externally.
            fuzzer
                .fuzz_loop(&mut stages, &mut executor, &mut $state, &mut mgr)
                .expect("fuzz_loop failed");
        }
    }};
}

#[cfg(not(feature = "std"))]
use run_engine_singlecore;
