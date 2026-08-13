<!-- SPDX-License-Identifier: Apache-2.0 -->

# Full logic-controller oracle corpus

This directory contains original, offline JMX plans for ELEM-003. Every case
is bounded, uses only built-in samplers/controllers, and records either a
deterministic JTL expectation or a declared static constraint contract for a
future Apache JMeter 5.6.3 differential run. The checked-in expectations are
static hypotheses: this corpus was not executed by Java, JMeter, a server, or
a subprocess.

The cases deliberately keep controller state visible through ordered Debug
Sampler labels and, where useful, expanded variables. RandomController and
RandomOrderController retain built-in upstream semantics, but because JMeter
5.6.3 does not expose a controller-local seed setter their plans use a static
constraint contract: one random child per RandomController iteration and each
child once for RandomOrderController, without a fixed random output order
claim. Throughput percentage selection and multi-thread Critical Section
scheduling use the same invariant contract.
Runtime cases use zero or one second limits and no network or external process.

| case | coverage |
| --- | --- |
| `basic-traversal` | Simple, finite/zero loops, Once Only, Interleave, nested order, disabled element, thread iterations |
| `conditional-state` | If true/false and evaluate-all modes, While false/LAST state, bounded failed-child transition |
| `throughput-modes` | Throughput Controller total and percentage modes with per-thread counters |
| `runtime-boundaries` | Runtime Controller zero-runtime and one-second deadline wire contracts with a finite 128-visit child cap |
| `transaction-modes` | Transaction Controller independent and parent samples, timer inclusion flag |
| `negative-wire-values` | Syntax-only invalid loop input, static `LoopController.loops=-1` forever boundary, plus upstream expired-runtime/missing-condition and built-in RandomController one-child-per-iteration invariant; never an executable oracle plan |
| `extended-controllers` | Random Order, Random, Switch, ForEach with visible values, disabled Module/Include/Recording, and single-thread Critical Section contracts |
| `lifecycle-groups` | SetupThreadGroup, main ThreadGroup, and PostThreadGroup ordering |
| `lifecycle-failure-stop` | Serialized setup/main/teardown groups, assertion failure, stopthread/stoptest, teardown, and null-result controller contracts |
| `critical-section-multi` | Two-thread named Critical Section lock invariant with per-thread identity |

Each case has a JMX plan (the negative case is explicitly isolated under
`negative-wire-values/syntax-static/`), `oracle.properties`, `case.json`,
`provenance.json`, and one or more files under `expected/`. Every manifest
declares finite thread, iteration, sample, plan-size, output-size, and wait
bounds. No raw JTL, log, or stale oracle artifact metadata is materialized in
this directory; every manifest says `ignored local evidence: none collected`.
A
future local run must remain outside the repository fixture tree.
`filename=false` is set in every properties file and each retained sample
contract explicitly requires `responseFile` to be absent. Deterministic
contracts retain exact thread identity (`tn`) and sent bytes (`sby`); static
constraint contracts list runtime fields outside their assertion surface
instead of silently applying normalization. The negative case's `-1` forever
loop is a wire-preservation constraint only; no static check may execute it.
