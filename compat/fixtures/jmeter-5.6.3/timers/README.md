<!-- SPDX-License-Identifier: Apache-2.0 -->

# Timer corpus

This directory is an original, static JMeter 5.6.3 corpus for timer
placement, additive delay, uniform random delay, unbounded Gaussian/Poisson
distributions, throughput pacing, synchronization, timer-factor handling, and
scheduler/ramp interaction.  The
plans use only built-in JMeter elements and local `DebugSampler` nodes; they
do not contact a service or depend on a data file.

Every case records the exact JMX and property-file hashes in `case.json` and
`provenance.json`.  The checked-in expectations describe the timer contract,
planned topology, and which runtime values remain unobserved.  Oracle
execution is intentionally not part of this static handoff: raw JTL and logs
belong under the ignored
`oracle-runs/timers/` tree after a separately authorized pinned-oracle run.
Each case owns its `oracle.properties`; there is no shared root property file.

Timer delays and result timing fields have explicit descriptor-only tolerance
plans pending a controlled-clock oracle run.  `ignored_fields` is empty in
these static JMX expectations: byte fields are retained and no JTL field is
dropped.  Timer property values, scope, class names, labels, and half-open
uniform/timer-factor bounds remain observable; runtime sample counts are
explicitly unobserved.  Gaussian and Poisson underlying supports are
documented separately from effective wait support: Gaussian's effective
pre-sampler wait is `[0, infinity)` while raw `Timer.delay()` output remains
unbounded below, and Poisson output is `[base, infinity)`.  The `external-*`
cases preserve BeanShell and JSR223 timer syntax while identifying both JVM
and plugin boundaries.  Scheduler/ramp cases distinguish TimerService delay
clipping and its `-1`
early-thread-stop sentinel from a sampler that has already started and can
overrun the boundary; the full timer-crossing outcome remains oracle-pending.
The `invalid-values` case records the scheduler-disabled
negative-ramp zero-clamp distinction and preserves scheduler-enabled invalid
fields for a future oracle check; it does not claim a runtime result or
successful execution.
