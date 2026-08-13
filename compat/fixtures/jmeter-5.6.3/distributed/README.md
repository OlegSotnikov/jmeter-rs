<!-- SPDX-License-Identifier: Apache-2.0 -->

# Apache JMeter 5.6.3 distributed/RMI static corpus

This directory is the original, deterministic static input corpus for
`DIST-001` through `DIST-004` and the `EXT-RMI-001`/`EXT-TLS-001` boundaries. It
contains no Java/JMeter distribution, worker process, shell runner, generated
worker data, keystore, JTL, log, or raw oracle artifact. The profile remains
external/planned; these files define the inputs and acceptance projections for
an isolated runner to execute later.

The corpus records the observable boundary described by the pinned profile and
research: a plan is copied in full to every selected worker, worker-local files
and dependencies are not copied, `-G` properties are sent only in the
`basic-R-G-X` and SSL scenarios, `-X` requests remote exit, and sample sender
modes retain their declared flush and response-data behavior. The passing
built-in sender matrix contains the nine factory aliases from the pinned 5.6.3
core JAR. `Hold` is represented only by two explicit negatives: the class is
present but has no factory alias, and its FQCN fallback lacks the required
public `RemoteSampleListener` constructor. Lowercase aliases, unknown/empty
modes, client/server property ownership, and the asynchronous end-of-test
ordering are also explicit static contracts. For `Asynch` and
`StrippedAsynch`, `TestEnded` followed by the final sentinel and
`processBatch` delivery is only a pinned source observation: execution remains
capability-unavailable until a positive `SenderDrainProof` hook observes
sentinel consumption and sender-thread termination. Callback-invocation and
delivered-event ordinals, `ProcessBatch` delivery kind, event/byte `EventAck`
counts, closed terminal accounting, and typed retry dispositions are recorded
without runtime observations. No Rust-native transport is presented as Java
RMI.

The pinned Apache JMeter 5.6.3 artifact SHA-512 is
`387fadca903ee0aa30e3f2115fdfedb3898b102e6b9fe7cc3942703094bd2e65b235df2b0c6d0d3248e74c9a7950a36e42625fd74425368342c12e40b0163076`.

## Static files

* `plan.jmx` is an original two-thread, two-iteration plan. It reads the
  relative `worker-local.txt` through a `CSVDataSet` and emits
  `distributed-worker-sample` Debug Sampler events with worker variables and
  properties visible. The plan-root data file is intentionally absent: the
  original one-line seed files under `inputs/worker-a` and `inputs/worker-b`
  document what the external runner must stage independently in each worker.
* `stop-plan.jmx` is an original one-thread scheduler plan with a 30-second
  bound and a 50 ms timer. It provides a bounded input for shutdown, immediate
  stop, and remote-exit cases.
* `properties/*.properties` contains deterministic loopback, RMI, SSL toggle,
  retry-policy, result-save, and sender-threshold inputs. Client files carry
  explicit `client.tries=3` and `client.retries_delay=250`; the static failure
  cases withhold worker-b registry and engine and classify the expected
  `java.rmi.ConnectException` as a startup-connect failure. The RMI hostname
  is supplied by `RMI_HOST_DEF` and `-Djava.rmi.server.hostname=127.0.0.1`,
  never by a `-q` JMeter property. Ephemeral keystore paths are not checked in.
* `case.json` is the repository-standard oracle-case manifest. Its command
  templates are local `jmeter -n` shape checks; the distributed `-r/-R/-G/-X`
  scenarios are recorded under `distributed_manifest` for the external runner.
* `expected/*.json` are comparator-valid schema-only projections. They preserve
  deterministic labels, worker/data-transfer rules, sender names, mode-specific
  thresholds and end flush obligations, negative fail-closed descriptors, and
  separate shutdown/stoptest/remote-exit contracts without fabricating a
  Java/RMI result or sample count. Bytes and sent-bytes remain retained fields;
  timing has explicit bounded/descriptor-only tolerances.
* `inputs/` contains distinct worker-local data, a worker-local classpath
  dependency probe, client decoys, and `ssl/README.md` typed protected
  references. The plan
  references the data through a `CSVDataSet`, the dependency marker through a
  second `CSVDataSet`, and the worker classpath through
  `TestPlan.user_define_classpath`.
* `provenance.json` pins the profile artifact and records the static origin,
  hashes, environment, and intentionally unavailable oracle execution.

The two workers should bind only to `127.0.0.1`. The static port model uses
base `1099`: registries are `base+0`/`base+1`, worker engines are `base+2` and
`base+3`, `client.rmi.localport` is `base+4`, its derived thread/sample
listeners are `client.rmi.localport+1`/`+2` (`base+5`/`base+6`), and the
controller UDP port is `base+7` (`1106` for the static base). The controller
commands are exactly `Shutdown` and `StopTestNow`, sent as UTF-8 token plus
LF. `-R 127.0.0.1:1099,127.0.0.1:1100` is the concrete
`remote_hosts` override for base `1099`; all runner endpoints must be derived
from the selected base and the complete eight-port block must be reserved.
A future external runner must allocate a free high base port, preserve these
offsets, create distinct worker-local inputs, withhold worker-b for the
partial-failure cases, generate temporary JKS material using the typed
path/channel/alias/certificate references, erase protected material during
cleanup, and keep all raw output outside this directory.

## Static acceptance

From the repository root, these checks require no Java, network, container, or
process lifecycle:

```sh
python3 -m json.tool compat/fixtures/jmeter-5.6.3/distributed/case.json >/dev/null
python3 -m json.tool compat/fixtures/jmeter-5.6.3/distributed/provenance.json >/dev/null
find compat/fixtures/jmeter-5.6.3/distributed -name '*.json' -print0 \
  | xargs -0 -n1 python3 -m json.tool >/dev/null
find compat/fixtures/jmeter-5.6.3/distributed -name '*.jmx' -print0 \
  | xargs -0 -n1 python3 -c 'import sys,xml.etree.ElementTree as ET; ET.parse(sys.argv[1])'
cargo xtask fixture-check --fixtures compat/fixtures/jmeter-5.6.3/distributed
git diff --check -- compat/fixtures/jmeter-5.6.3/distributed
```

`cargo xtask fixture-check` verifies every manifest reference, schema header,
profile ID, safe path, and SHA-256. The first four commands are useful when
Cargo is unavailable. In this standalone invocation the command is expected
to exit nonzero because the active profile is evaluated globally and still
reports unrelated fixture-family/profile-boundary diagnostics; the
distributed-specific manifest, safety, schema, and hash checks are otherwise
clean. None of these checks establishes RMI compatibility.

## External runner gap

The Java/JMeter distributed runner is deliberately not part of this static
ownership slice. No run has been performed here, and no conformance status or
profile evidence is promoted. The recorder half of the broader distributed /
recorder / TLS union is outside this standalone case, so `TEST-004` is not
claimed here. A future runner must record exact Java/JMeter versions, generated
port and keystore metadata, worker identities, sender-mode JTL projections,
retries, stop/exit outcomes, and raw artifacts under an ignored run root before
any profile row can change status.
