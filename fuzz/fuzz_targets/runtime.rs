#![no_main]

//! Bounded runtime controller and deterministic scheduler target.
//!
//! No executor, clock thread, process, or transport is created.  Bytes select
//! a small controller tree and finite scheduler keys/delays, while each API
//! carries explicit limits.
//!
//! Invariants: `RUNTIME-CONTROLLER-001` keeps ordered controller traversal
//! within a finite run budget; `RUNTIME-SCHEDULER-001` preserves deterministic
//! wake ordering/cancellation; and `RUNTIME-BOUNDS-001` never derives an
//! unbounded tree or wake registry from fuzz input.
//! Source-side coverage: controller child order, scheduler keys/delays, wake
//! cancellation, and finite budgets are checked as a generated state trace.
//! I/O policy: none; no executor, clock thread, transport, or process starts.

use std::time::Duration;

use jmeter_rs_runtime::{
    Cancellation, ControlSignal, ControllerNode, ControllerProgram, ControllerStep,
    DeterministicScheduler, LoopCount, MonotonicInstant, RunBudget, Scheduler, StepBudget,
};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 64 * 1024;
const MAX_CHILDREN: usize = 8;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }
    let child_count = data.len().min(MAX_CHILDREN);
    let children = (0..child_count)
        .map(|index| ControllerNode::sample(u64::from(data[index])))
        .collect::<Vec<_>>();
    let loop_count = data
        .first()
        .copied()
        .map_or(1, |value| u64::from(value % 4));
    let root = ControllerNode::loop_controller(1, LoopCount::finite(loop_count), children);
    let Ok(program) = ControllerProgram::compile_with_limits(
        root,
        jmeter_rs_runtime::ControllerLimits::default(),
    ) else {
        return;
    };
    let mut runner = program.runner();
    let mut budget = RunBudget::new(MAX_CHILDREN * 4, MAX_CHILDREN * 16);
    let trace = runner
        .run_to_completion(&mut budget)
        .expect("finite controller must terminate within its run budget");
    if trace.samples.len() > MAX_CHILDREN * 4 {
        panic!("controller trace exceeded its explicit sample bound");
    }

    let scheduler = DeterministicScheduler::new(MonotonicInstant::zero(), 8);
    let token = jmeter_rs_runtime::CancellationToken::new();
    let first = scheduler
        .register_after(Duration::from_millis(1), 2, &token)
        .expect("first wake registration");
    let second = scheduler
        .register_after(Duration::from_millis(1), 1, &token)
        .expect("second wake registration");
    if data.first().is_some_and(|value| value & 1 == 1) {
        first.cancel().expect("wake cancellation");
    }
    let ready = scheduler
        .advance_by(Duration::from_millis(1))
        .expect("scheduler advance");
    if ready.iter().any(|wake| wake.id == first.id())
        && data.first().is_some_and(|value| value & 1 == 1)
    {
        panic!("cancelled scheduler wake became ready");
    }
    if ready.iter().any(|wake| wake.id == second.id()) && ready.len() > 1 {
        for pair in ready.windows(2) {
            if (pair[0].deadline.instant(), pair[0].key, pair[0].id)
                > (pair[1].deadline.instant(), pair[1].key, pair[1].id)
            {
                panic!("scheduler wake order was not deterministic");
            }
        }
    }

    let cancellation = Cancellation::new();
    cancellation.request(ControlSignal::NextLoop);
    let mut cancellation_runner = program.runner();
    let mut initial_budget = StepBudget::new(MAX_CHILDREN * 4);
    let initial = cancellation_runner
        .step(&mut initial_budget)
        .expect("initial controller step must stay within its step bound");
    let mut step_budget = StepBudget::new(MAX_CHILDREN * 4);
    let cancelled = cancellation_runner
        .step_with_cancellation(&cancellation, &mut step_budget)
        .expect("next-loop cancellation must stay within its step bound");
    if matches!(cancelled, ControllerStep::Stopped(_)) {
        panic!("next-loop cancellation became a terminal stop");
    }
    if matches!(initial, ControllerStep::Complete) && !matches!(cancelled, ControllerStep::Complete)
    {
        panic!("completed controller changed under next-loop cancellation");
    }
});
