<!-- SPDX-License-Identifier: Apache-2.0 -->

# Distributed worker-local inputs

The two `worker-local.txt` files are original, one-line CSV inputs staged into
separate worker roots by a future external runner. Their contents intentionally
differ. JMeter RMI transfers the JMX plan and run-scoped properties, not these
worker-local data files.

`dependencies/fixture-dependency.marker` is a harmless text marker for the
worker-local dependency contract. It stands in for a separately provisioned
dependency identity; no JAR, plugin, or executable dependency is distributed
with this corpus. A worker may use the marker to prove that dependency
references are resolved locally, while the remote plan transfer must not carry
its contents. The plan's `TestPlan.user_define_classpath=worker-classpath` and
dependency `CSVDataSet` reference the worker-local classpath probe
`dependencies/worker-classpath/fixture-dependency.marker`.

`client/worker-local.txt` and `client/fixture-dependency.marker` are deliberate
client decoys. A distributed run must not use either decoy to satisfy a worker
data or dependency lookup; they are not transferred to workers.
