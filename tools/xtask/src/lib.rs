// SPDX-License-Identifier: Apache-2.0
//! Reproducible repository validation tasks.
//!
//! The repository checks in this crate are deliberately bounded and explicit.
//! They validate compatibility inventory, fixture provenance, and Cargo
//! workspace policy; generated-file commands use closed, declared target
//! catalogs and only rewrite their explicitly owned outputs.
//!
//! The command surface is the repository harness boundary for `TEST-001` and
//! the cross-platform/performance policy boundary for `TEST-005`.  Commands
//! that depend on the active profile admit dependent checks only after profile
//! validation succeeds; planned standalone release operations remain explicit
//! CI/tooling gates until they have their own typed validator.
//!
//! The small dependency set is intentional: `serde_json` 1.0.151 (MIT or
//! Apache-2.0, MSRV 1.71, `std` only) parses the checked-in JSON documents,
//! `toml` 1.1.4 (MIT or Apache-2.0, MSRV 1.85, `parse` + `serde`) parses Cargo
//! manifests, and `sha2` 0.11.0 (MIT or Apache-2.0, MSRV 1.85, default
//! features disabled) verifies fixture hashes.  The validator invokes
//! `cargo metadata` directly rather than adding the larger `cargo_metadata`
//! object model; no dependency needs network or filesystem access at runtime
//! beyond the explicit repository paths being checked.

mod diagnostics;
mod external_acceptance;
mod fixtures;
mod gui_acceptance;
mod http_acceptance;
mod policy;
mod profile;
mod profile_references;
mod property_inventory;
mod workspace;

use std::path::{Path, PathBuf};

pub use diagnostics::{Diagnostic, Diagnostics};
pub use profile_references::Action as ProfileReferencesAction;

const DEFAULT_PROFILE_ID: &str = "jmeter-5.6.3";
const DEFAULT_PROFILE_FILE: &str = "jmeter-5.6.3.json";

/// A repository check exposed by `cargo xtask`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Command {
    /// Validate the active compatibility profile and its inventory.
    ProfileCheck,
    /// Validate materialized oracle fixture manifests and provenance.
    FixtureCheck,
    /// Validate workspace metadata, inheritance, and dependency direction.
    WorkspaceCheck,
    /// Validate fuzz-corpus provenance and deterministic performance policy.
    PolicyCheck,
    /// Validate the static Decision 0007 external-adapter acceptance manifest.
    ExternalAcceptance,
    /// Validate Decision 0006's static HTTP acceptance matrix.
    HttpAcceptance,
    /// Validate the static Decision 0002 GUI acceptance contract.
    GuiAcceptanceCheck,
    /// Generate or check the pinned CFG-002 property inventory.
    PropertyInventory,
    /// Check or safely regenerate declared profile/source hash references.
    ProfileReferences,
}

impl Command {
    /// The currently implemented command set, in canonical help/dispatch order.
    ///
    /// Keeping this catalog next to the enum gives callers a single exhaustive
    /// source for command inventory tests.  A command must be added here when
    /// its dispatch arm is added; planned standalone release operations remain
    /// outside this catalog until they have a real validator and diagnostics.
    pub const ALL: [Self; 9] = [
        Self::ProfileCheck,
        Self::FixtureCheck,
        Self::WorkspaceCheck,
        Self::PolicyCheck,
        Self::ExternalAcceptance,
        Self::HttpAcceptance,
        Self::GuiAcceptanceCheck,
        Self::PropertyInventory,
        Self::ProfileReferences,
    ];

    /// Return the canonical command spelling used by `cargo xtask`.
    #[must_use]
    pub const fn canonical_name(self) -> &'static str {
        match self {
            Self::ProfileCheck => "profile-check",
            Self::FixtureCheck => "fixture-check",
            Self::WorkspaceCheck => "workspace-check",
            Self::PolicyCheck => "policy-check",
            Self::ExternalAcceptance => "external-acceptance",
            Self::HttpAcceptance => "http-acceptance",
            Self::GuiAcceptanceCheck => "gui-acceptance",
            Self::PropertyInventory => "property-inventory",
            Self::ProfileReferences => "profile-references",
        }
    }
}

pub use property_inventory::Action as PropertyInventoryAction;

/// Options shared by repository checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Options {
    /// Repository root containing `Cargo.toml`, `compat`, and `docs`.
    pub root: PathBuf,
    /// Optional compatibility profile path, relative to `root` when not absolute.
    pub profile: Option<PathBuf>,
    /// Optional fixture root, relative to `root` when not absolute.
    pub fixtures: Option<PathBuf>,
    /// Action for the CFG-002 property inventory command.
    pub property_inventory_action: Option<PropertyInventoryAction>,
    /// Optional local pinned-distribution properties directory.
    pub property_inventory_source: Option<PathBuf>,
    /// Optional generated CFG-002 inventory output path.
    pub property_inventory_output: Option<PathBuf>,
    /// Action for declared profile/source reference validation.
    pub profile_reference_action: Option<ProfileReferencesAction>,
    /// Optional Decision 0007 external-acceptance manifest path.
    pub external_acceptance_manifest: Option<PathBuf>,
    /// Whether the HTTP acceptance command was explicitly requested in check mode.
    pub http_acceptance_check: bool,
}

impl Options {
    /// Construct options rooted at the supplied path.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            profile: None,
            fixtures: None,
            property_inventory_action: None,
            property_inventory_source: None,
            property_inventory_output: None,
            profile_reference_action: None,
            external_acceptance_manifest: None,
            http_acceptance_check: false,
        }
    }

    fn profile_path(&self) -> PathBuf {
        self.profile
            .as_deref()
            .map(|path| resolve_path(&self.root, path))
            .unwrap_or_else(|| {
                self.root
                    .join("compat")
                    .join("profiles")
                    .join(DEFAULT_PROFILE_FILE)
            })
    }

    fn fixtures_path(&self, profile_id: &str) -> PathBuf {
        self.fixtures
            .as_deref()
            .map(|path| resolve_path(&self.root, path))
            .unwrap_or_else(|| self.root.join("compat").join("fixtures").join(profile_id))
    }

    fn property_inventory_source_path(&self) -> Option<PathBuf> {
        self.property_inventory_source
            .as_deref()
            .map(|path| resolve_path(&self.root, path))
    }

    fn property_inventory_output_path(&self) -> Option<PathBuf> {
        self.property_inventory_output
            .as_deref()
            .map(|path| resolve_path(&self.root, path))
    }

    fn external_acceptance_manifest_path(&self, profile_id: &str) -> PathBuf {
        self.external_acceptance_manifest
            .as_deref()
            .map(|path| resolve_path(&self.root, path))
            .unwrap_or_else(|| {
                self.root
                    .join("compat")
                    .join("fixtures")
                    .join(profile_id)
                    .join("external-acceptance.json")
            })
    }

    /// Resolve the HTTP fixture root for the active profile.
    ///
    /// HTTP acceptance validates the profile itself, but its existing checker
    /// accepts the fixture root as an explicit argument.  Resolve that root
    /// from the validated profile ID so a custom profile cannot accidentally
    /// read the default JMeter fixture tree.  Invalid profiles fall back to
    /// the default path only for the checker to report the profile error; no
    /// dependent fixture validation is admitted for an invalid profile.
    fn http_acceptance_fixture_path(&self) -> PathBuf {
        let profile_path = self.profile_path();
        let (profile_diagnostics, profile_index) = profile::check(&self.root, &profile_path);
        if profile_diagnostics.is_empty()
            && let Some(profile_index) = profile_index
        {
            return self.fixtures_path(&profile_index.profile_id);
        }
        self.fixtures_path(DEFAULT_PROFILE_ID)
    }
}

fn run_profile_dependent<F>(options: &Options, check: F) -> Diagnostics
where
    F: FnOnce(&Options, &profile::ProfileIndex) -> Diagnostics,
{
    let profile_path = options.profile_path();
    let (mut diagnostics, profile_index) = profile::check(&options.root, &profile_path);

    // Do not consume a partially populated index.  Profile validation is the
    // admission gate for every dependent catalog; using an index alongside
    // profile errors can select untrusted paths or produce misleading
    // downstream evidence.  The profile diagnostics already make the command
    // fail, so this remains fail-closed without inventing a second error.
    if diagnostics.is_empty()
        && let Some(profile_index) = profile_index.as_ref()
    {
        diagnostics.extend(check(options, profile_index));
    }
    diagnostics.sort_deterministically();
    diagnostics
}

/// Run one repository check and return deterministic diagnostics.
pub fn run(command: Command, options: &Options) -> Diagnostics {
    match command {
        Command::ProfileCheck => profile::check(&options.root, &options.profile_path()).0,
        Command::FixtureCheck => run_profile_dependent(options, |options, profile| {
            fixtures::check(
                &options.root,
                &options.fixtures_path(&profile.profile_id),
                profile,
            )
        }),
        Command::WorkspaceCheck => workspace::check(&options.root),
        Command::PolicyCheck => run_profile_dependent(options, |options, profile| {
            policy::check(
                &options.root,
                &options.fixtures_path(&profile.profile_id),
                profile,
            )
        }),
        Command::ExternalAcceptance => run_profile_dependent(options, |options, profile| {
            let profile_path = options.profile_path();
            external_acceptance::check(
                &options.root,
                &options.external_acceptance_manifest_path(&profile.profile_id),
                &profile_path,
                profile,
            )
        }),
        Command::HttpAcceptance => http_acceptance::check(
            &options.root,
            &options.profile_path(),
            &options.http_acceptance_fixture_path(),
            options.http_acceptance_check,
        ),
        Command::GuiAcceptanceCheck => run_profile_dependent(options, |options, profile| {
            let profile_path = options.profile_path();
            gui_acceptance::check(
                &options.root,
                &options.fixtures_path(&profile.profile_id),
                profile,
                &profile_path,
            )
        }),
        Command::PropertyInventory => property_inventory::run(
            &options.root,
            options
                .property_inventory_action
                .unwrap_or(PropertyInventoryAction::Check),
            options.property_inventory_source_path().as_deref(),
            options.property_inventory_output_path().as_deref(),
        ),
        Command::ProfileReferences => profile_references::run(
            &options.root,
            &options.profile_path(),
            options
                .profile_reference_action
                .unwrap_or(profile_references::Action::Check),
        ),
    }
}

fn resolve_path(root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    }
}

#[cfg(test)]
mod tests {
    use super::{Command, Options, resolve_path};
    use std::path::Path;

    #[test]
    fn command_catalog_has_one_canonical_name_per_dispatch_variant() {
        let names = Command::ALL
            .into_iter()
            .map(Command::canonical_name)
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            [
                "profile-check",
                "fixture-check",
                "workspace-check",
                "policy-check",
                "external-acceptance",
                "http-acceptance",
                "gui-acceptance",
                "property-inventory",
                "profile-references",
            ]
        );
    }

    #[test]
    fn options_are_value_types_for_cli_parser_tests() {
        let options = Options::new("/repo");
        assert_eq!(options, Options::new("/repo"));
        assert_ne!(options, Options::new("/other"));
    }

    #[test]
    fn relative_paths_resolve_against_root_but_absolute_paths_are_preserved() {
        let root = Path::new("/repo");
        assert_eq!(
            resolve_path(root, Path::new("compat/profile.json")),
            Path::new("/repo/compat/profile.json")
        );
        assert_eq!(
            resolve_path(root, Path::new("/tmp/profile.json")),
            Path::new("/tmp/profile.json")
        );
    }

    #[test]
    fn profile_dependent_gates_do_not_run_after_profile_diagnostics() {
        let options = Options::new("/path/that/does/not/exist");
        let mut called = false;
        let diagnostics = super::run_profile_dependent(&options, |_, _| {
            called = true;
            super::Diagnostics::default()
        });
        assert!(!diagnostics.is_empty());
        assert!(!called);
    }
}
