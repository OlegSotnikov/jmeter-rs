<!-- SPDX-License-Identifier: Apache-2.0 -->

# Security policy

This project is experimental. Its current command supports only bounded native
execution for enabled `ThreadGroup`/`TestPlan` trees containing
`GenericController`, `LoopController`, and `DebugSampler` nodes (with response
assertions), plus CSV report-only dashboard processing; Java/JSR223, plugins,
RMI, GUI, unsupported samplers/controllers, and other capabilities return typed
errors. The libraries and fixture tooling still process untrusted JMX/JTL
inputs, and planned adapters may invoke external processes or plugin runtimes
and send traffic to operator-selected endpoints. Do not use it with production
credentials or sensitive plans until the relevant security controls and tests
are documented.

## Reporting a vulnerability

Private vulnerability reporting is not configured for this repository yet.
Do not disclose sensitive details in a public issue or pull request, and do not
send a private report until a maintainer-published secure channel is confirmed.
Once GitHub private vulnerability reporting is enabled, the intended advisory
form is:

<https://github.com/OlegSotnikov/jmeter-rs/security/advisories/new>

No email address or alternate private reporting channel has been configured.
Maintainers must enable and test the advisory route, or publish an equivalent
secure contact, before accepting community reports or making a release. If
the form is unavailable, do not include sensitive details in a public report.

Please include a concise impact description, affected revision or profile,
reproduction steps or a minimized fixture, and any suggested mitigation. Do
not attach credentials, private keys, customer data, or live endpoint details.

The project will acknowledge receipt when a private report is accessible,
triage its impact, and coordinate disclosure with the reporter. No response
time or remediation timeline is promised while the project is experimental.
