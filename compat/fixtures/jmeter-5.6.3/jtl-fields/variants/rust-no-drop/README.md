<!-- SPDX-License-Identifier: Apache-2.0 -->

# Rust no-drop/parser variants

These inputs deliberately exercise the Rust parser contract, not the
JMeter-writer wire contract.  Unknown attributes (`case__id`, `comma__value`)
and recursively unknown child elements (`rootExtension` at the root, and
`pluginData`/`pluginChild` under the sample) must remain available to a no-drop
projection.  Root-child placement and child order are part of this variant.
The doubled underscores are therefore intentional here; the JMeter writer
inputs under `inputs/xml/` use the single-underscore sample variable names
emitted by JMeter.
