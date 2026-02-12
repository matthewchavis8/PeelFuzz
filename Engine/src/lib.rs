//! PeelFuzz Engine - LibAFL-based fuzzing library for C/C++ targets
//!
//! Provides a C ABI for integrating LibAFL fuzzing into native applications.

#![cfg_attr(not(feature = "std"), no_std)]
#![allow(dead_code)]

pub mod sanitizer_coverage;

#[cfg(feature = "std")]
mod targets;

#[cfg(feature = "std")]
use std::path::PathBuf;

#[cfg(feature = "std")]
use libafl::{
    corpus::Corpus,
    corpus::{InMemoryCorpus, OnDiskCorpus},
    executors::{ExitKind, inprocess::InProcessExecutor},
    feedbacks::{CrashFeedback, MaxMapFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::RandBytesGenerator,
    inputs::BytesInput,
    mutators::{havoc_mutations::havoc_mutations, scheduled::HavocScheduledMutator},
    observers::StdMapObserver,
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::{HasCorpus, StdState},
};

#[cfg(feature = "std")]
use libafl_bolts::{current_nanos, rands::StdRand, tuples::tuple_list};

#[cfg(feature = "std")]
use core::num::NonZero;

use sanitizer_coverage::{MAP_SIZE, SIGNALS_PTR};

/// Shared fuzzer engine. Takes a harness and runs the full LibAFL pipeline.
/// New fuzz_* entry points only need to build a harness and pass it here.
#[cfg(feature = "std")]
unsafe fn run_fuzzer(mut harness: impl FnMut(&BytesInput) -> ExitKind) {
    if SIGNALS_PTR.is_null() {
        sanitizer_coverage::init_coverage();
    }

    let observer = StdMapObserver::from_mut_ptr("signals", SIGNALS_PTR, MAP_SIZE);
    let mut feedback = MaxMapFeedback::new(&observer);
    let mut objective = CrashFeedback::new();

    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        InMemoryCorpus::new(),
        OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap(),
        &mut feedback,
        &mut objective,
    )
    .unwrap();

    let mon = libafl::monitors::SimpleMonitor::new(|s| println!("{s}"));
    let mut mgr = libafl::events::SimpleEventManager::new(mon);
    let scheduler = QueueScheduler::new();
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let mut executor = InProcessExecutor::new(
        &mut harness,
        tuple_list!(observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
    )
    .unwrap();

    if state.corpus().count() == 0 {
        let mut generator = RandBytesGenerator::new(NonZero::new(32).unwrap());
        state
            .generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 8)
            .unwrap();
    }

    let mutator = HavocScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .unwrap();
}

/// Fuzz a C target that takes a byte buffer and its length.
#[cfg(feature = "std")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fuzz_byte_size(target_fn: targets::CTargetFn) {
    run_fuzzer(targets::bytes_harness(target_fn));
}
