# Repository and publication baseline

This document records the repository-state check and the publication,
licensing, and release controls for `jmeter-rs`. It is deliberately a
repository baseline; it does not choose the Rust application architecture or
implement application code.

Checked on 2026-08-12 (UTC). The canonical repository supplied for this work
is [OlegSotnikov/jmeter-rs](https://github.com/OlegSotnikov/jmeter-rs).

> Historical snapshot notice: the repository-state narrative below records
> the empty/unborn baseline at that time. The current worktree contains the
> Rust workspace and remains uncommitted; this document is not evidence that a
> release, GitHub setting, security channel, or publication gate is ready.

## Historical state and exact local changes

At baseline time, the repository owner had created the GitHub repository. A fresh
anonymous GitHub API request returned HTTP 200 and described it as:

- public (`private: false`, `visibility: public`);
- size `0`, with no license, language, topics, or commits reported;
- default branch `main`;
- `created_at` and `updated_at` of `2026-08-12T04:06:41Z`.

`git ls-remote --heads --tags https://github.com/OlegSotnikov/jmeter-rs.git`
completed successfully with no output. That is the important Git-level check:
the remote has no branch or tag refs. The earlier check, before the owner
created it, returned GitHub's repository-not-found response; the current
empty-repository result supersedes that check.

Before initialization the workspace contained the existing engineering
research document at `docs/research/rust-testing-strategy.md` and had no
`.git` directory. Because the remote was verified empty, local Git was
initialized with:

```text
git init -b main
git remote add origin https://github.com/OlegSotnikov/jmeter-rs.git
```

The resulting local state is an unborn `main` branch with the `origin` fetch
and push URL above. The working tree still has no commits; the existing
`docs/` content is untracked. No commit, push, branch protection change,
repository setting change, issue, release, or other remote write was made.

The first commit should be made only after the owner reviews the legal and
publication files described below. Do not force-push an unrelated history if
someone initializes the GitHub repository in the meantime. Re-run
`git ls-remote` and inspect the remote's first commit before publishing.

## License choice and Apache-2.0 obligations

The project is an independent Rust implementation/compatibility project, not
an Apache Software Foundation project. If the copyright holder chooses the
Apache License, Version 2.0 for original `jmeter-rs` code, use the SPDX
identifier `Apache-2.0` consistently and add the complete English license text
as a root-level `LICENSE` file. The authoritative terms are the
[Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0.html);
the ASF's [license-application guidance](https://www.apache.org/legal/apply-license)
is useful operational guidance but is not a substitute for the license or
legal advice.

Before the first release:

1. Put the full Apache 2.0 text in `LICENSE` at the top of the source tree.
   Do not replace it with a link or a shortened summary.
2. Add a short `SPDX-License-Identifier: Apache-2.0` header to original
   source and documentation files where practical. Do not add the project's
   header to copied third-party files; preserve their original headers and
   license text.
3. Keep a root `NOTICE` under version control once the project distributes a
   release. For a third-party project, the exact contents must be truthful and
   should contain only required attribution notices. A NOTICE file is not a
   place for marketing copy or a claim of Apache affiliation. The
   [ASF guidance on assembling LICENSE and NOTICE](https://infra.apache.org/licensing-howto.html)
   explains that those files must match the contents of the distribution.
4. If the distribution contains only original project code and dependencies
   whose notices do not require a root addition, do not invent an Apache
   Software Foundation copyright or the ASF's standard product notice. Put the
   project's own copyright and the non-affiliation/trademark wording in an
   appropriate project document, and keep `NOTICE` limited to legally required
   notices. Have the copyright holder obtain legal review if the chosen
   license/notice arrangement is uncertain.
5. For every third-party dependency or fixture, record its source, version,
   license, copyright/attribution requirements, and whether it is included in
   source or binary artifacts. A generated third-party notices report should
   be checked into or attached to binary releases when the included dependency
   licenses require it.

Apache License section 4 requires, among other things, redistributing a copy
of the license, retaining applicable copyright/patent/trademark/attribution
notices, preserving applicable NOTICE text, and marking modified files. It
does not grant permission to use a licensor's product names as a product
brand. Keep the license obligations separate from ASF project-specific policy:
the [ASF source-header and copyright policy](https://www.apache.org/legal/src-headers.html)
is a policy for ASF distributions, while its third-party-work rules are a
useful model for preserving upstream notices.

### Apache JMeter materials

The Rust project may use Apache JMeter as a behavioral oracle without making
the Apache JMeter distribution part of every `jmeter-rs` source or binary
release. If a CI job downloads JMeter for comparison, pin the exact release,
archive checksum, and (where provided) OpenPGP signature/key; do not fetch an
unversioned “latest”. Apache's [JMeter download page](https://jmeter.apache.org/download_jmeter.cgi)
describes the release checksum/signature files. Record the selected JMeter
version and hashes in the conformance manifest and CI logs.

If a source archive, container, installer, or binary release actually bundles
Apache JMeter or copied JMeter files, retain the corresponding upstream
`LICENSE`, `NOTICE`, and third-party notices in that distribution. The
official [JMeter LICENSE](https://github.com/apache/jmeter/blob/master/LICENSE),
[JMeter NOTICE](https://github.com/apache/jmeter/blob/master/NOTICE), and
[JMeter README legal-information section](https://github.com/apache/jmeter/blob/master/README.md)
are the primary references. Do not copy JMeter's notice into a release that
does not contain JMeter; do not represent JMeter's copyright as copyright in
the Rust implementation.

JMeter's own documentation warns that a JMX plan can include arbitrary code
and that even opening an untrusted plan may execute it. Treat oracle plans,
plugins, and downloaded archives as untrusted inputs: run them in an isolated,
least-privileged job/container with no production credentials or sensitive
network access. See the official [JMeter security model](https://jmeter.apache.org/security.html).

## Package metadata and source-distribution policy

Each publishable Cargo package should declare metadata explicitly in its
`Cargo.toml`; internal-only packages should be marked non-publishable. The
workspace should eventually review, at minimum:

```toml
name = "jmeter-rs"                 # final crates.io name requires a check
version = "0.1.0"                 # use the project's selected version policy
edition = "<explicit-edition>"
rust-version = "<declared-msrv>"
license = "Apache-2.0"
description = "Rust compatibility implementation for Apache JMeter test plans"
repository = "https://github.com/OlegSotnikov/jmeter-rs"
readme = "README.md"
```

The snippet is a metadata checklist, not an instruction to select an edition,
MSRV, or release version in this baseline. Use the same repository URL and
license identifier in every published crate. Add `homepage`, `documentation`,
keywords, and crates.io categories only when they are accurate. Avoid putting
credentials, machine paths, generated load-test results, private endpoints,
or unreviewed JMX plans in `readme`, package metadata, examples, or packaged
files. Use Cargo's explicit `include`/`exclude` policy for published packages
and run `cargo package --locked --allow-dirty` only in a controlled local check
(the final release check must use a clean tree).

Commit `Cargo.lock` for binaries, oracle tools, and other executable packages;
run release and CI builds with `--locked`. If library crates are published,
apply the project's declared lockfile policy consistently and explain any
exception. Run `cargo metadata --locked` and inspect the package contents
before publishing. Keep generated reports, JMeter archives, local plugin JARs,
and credentials out of crates.io packages unless they are intentionally
licensed and included.

## GitHub branch and repository controls

After the first commit, configure a GitHub ruleset/branch protection policy for
`main`. It should require pull requests, at least one appropriate review,
conversation resolution, the complete required CI status set, and an
up-to-date branch before merge. Disallow force-pushes and branch deletion;
restrict direct pushes to maintainers or a narrowly defined release role.
Protect release tags (for example, an immutable `v*` tag policy), require
review for workflow-file changes, and enable Dependabot/security alerts where
available. Keep rulesets documented in the repository so a mirror or future
host can reproduce them.

Do not claim that these controls are active yet: no GitHub settings were
changed during this baseline. They require an authenticated owner/admin
operation after the initial repository files exist.

## CI, oracle, and release provenance

This section is policy guidance, not a statement that every listed lane or
release workflow is currently configured. Current automation has a pinned Rust
lane and dependency/security checks. It defines a manual/scheduled JMeter
fixture-smoke workflow, but that workflow is unconditionally disabled; current
automation does not execute Java or JMeter. Release provenance and full
differential gates remain pending.

The minimum CI policy should have separate, visible jobs for formatting,
linting, unit/integration tests, package/content checks, dependency/license
review, and the pinned JMeter conformance matrix. A release must not silently
turn a failed or unavailable oracle run into a passing compatibility claim.
Keep the following values in every conformance and release record:

- source commit and exact dirty-tree status;
- release/profile version, selected Apache JMeter archive and the digest
  algorithm/value declared by that profile (SHA-512 for the current 5.6.3
  profile), Java runtime, OS image, locale, timezone, and relevant plugin
  checksums;
- Rust toolchain, target triple, Cargo.lock hash, and build feature set;
- test-plan/fixture identifiers, random seed/clock mode, normalization rules,
  expected differences, and raw comparison artifacts;
- artifact checksums and the workflow/run identifier that produced them.

Use a clean checkout for release builds and set reproducibility inputs such as
UTC, a fixed locale, and `SOURCE_DATE_EPOCH` where the toolchain permits it.
Pin third-party GitHub Actions to reviewed commit SHAs rather than mutable
tags, give jobs the smallest possible `permissions` set (normally
`contents: read`), and keep secrets out of fork pull-request jobs. GitHub's
[Actions security-hardening guidance](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions)
and [OIDC hardening guidance](https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect)
cover these controls.

For release provenance, publish checksums and a signed release manifest. Use
GitHub's [artifact attestations](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations)
or an equivalent keyless/Sigstore or maintainer-signing process, and document
how a user verifies it. Attach the source commit, toolchain, dependency lock
hash, and JMeter profile to the release. Do not call a build reproducible or
verified merely because the workflow completed; retain verification output and
fail the release if required provenance or license accounting is absent.

## Naming, trademark, and user-facing wording

The ASF states that Apache project names, including Apache JMeter/JMeter, are
ASF trademarks. The official JMeter site identifies “Apache”, “Apache JMeter”,
“JMeter”, the Apache feather, and the Apache JMeter logo as ASF trademarks.
See the [ASF trademark policy](https://www.apache.org/foundation/marks/),
[ASF trademark FAQ](https://www.apache.org/foundation/marks/faq/), and the
official [JMeter site footer/download page](https://jmeter.apache.org/download_jmeter.cgi).

Use the mark only for truthful, nominative compatibility statements. A safe
first prominent description is:

> `jmeter-rs` is an independent Rust project for running and analyzing test
> plans intended to be compatible with Apache JMeter. It is not affiliated
> with, sponsored by, or endorsed by the Apache Software Foundation.

Use “Apache JMeter” on first reference, link to the official JMeter site, and
avoid the ASF/JMeter logos. Do not call the project “Apache JMeter for Rust”,
“official JMeter”, or otherwise imply that ASF publishes, certifies, or
endorses it. The repository/package identifier `jmeter-rs` is retained here
because it was supplied by the owner; before public marketing or a crates.io
release, have the owner review whether the name could create trademark/source
confusion and seek specialist advice if needed. The ASF policy says third
parties generally may not use ASF marks in third-party software branding, even
though nominative references to the Apache product are allowed.

## Secret and sensitive-data hygiene

Before the first commit and on every release:

- add a reviewed `.gitignore` for build output, local `.env`/property files,
  credentials, private keys/certificates, JMeter result files, local plugin
  directories, and editor/OS state; do not use an overly broad rule that hides
  source fixtures silently;
- keep passwords, bearer tokens, cookies, client keys, cloud credentials,
  personal endpoints, and real customer payloads out of JMX/JTL/XML fixtures,
  examples, documentation, test logs, and command-line arguments;
- use obvious placeholders and local/ephemeral test servers, with a separate
  reviewed allowlist for fixtures that intentionally exercise credential
  handling;
- run a maintained secret scanner and dependency/license scanner in CI and
  enable GitHub secret scanning/push protection where the account plan
  supports it;
- redact headers, URLs, environment values, request bodies, plugin output, and
  failure artifacts before upload; do not print secrets through `--debug` or
  shell tracing;
- expose release credentials only to the release job, use short-lived OIDC
  credentials where possible, and keep forked pull requests unable to access
  them;
- if a secret is ever committed, revoke/rotate it immediately, then perform a
  coordinated history cleanup and verify caches/artifacts. Removing the file
  in a later commit is not sufficient.

The security boundary is particularly important for JMX plans and JMeter
plugins, because the official JMeter security model assumes that input plans
are trusted. Conformance tests should therefore use sanitized fixtures and
isolated credentials by construction.

## Publication checklist

This is a pre-publication checklist, not a readiness assertion. The first
release still requires reviewed metadata, active reporting/security channels,
clean-tree provenance, and evidence-backed profile rows.

Before the first push, the owner should confirm:

- root `LICENSE` and a truthful `NOTICE`/third-party attribution strategy are
  present and reviewed;
- the README uses the independent-project wording and contains no ASF logo or
  implied endorsement;
- Cargo metadata, package contents, lockfile policy, and crate names are
  reviewed;
- `.gitignore`, secret scanning, CI permissions, pinned tool versions, and
  branch/ruleset settings are prepared;
- the clean-tree CI and release workflow can identify source, toolchain,
  dependencies, JMeter oracle profile, checksums, and artifact provenance;
- `git status`, `git diff --check`, license checks, secret scans, and the
  appropriate test suite pass locally.

This baseline does not push, commit, alter GitHub settings, download or bundle
JMeter, or select application architecture.
