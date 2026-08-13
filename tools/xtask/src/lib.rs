// SPDX-License-Identifier: Apache-2.0
//! Reproducible repository validation tasks.
//!
//! The repository checks in this crate are deliberately bounded and explicit.
//! They validate compatibility inventory, fixture provenance, and Cargo
//! workspace policy; generated-file commands use closed, declared target
//! catalogs and only rewrite their explicitly owned outputs.
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

pub use property_inventory::Action as PropertyInventoryAction;

/// Options shared by repository checks.
#[derive(Clone, Debug)]
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
                    .join("jmeter-5.6.3.json")
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
}

/// Run one repository check and return deterministic diagnostics.
pub fn run(command: Command, options: &Options) -> Diagnostics {
    match command {
        Command::ProfileCheck => profile::check(&options.root, &options.profile_path()).0,
        Command::FixtureCheck => {
            let profile_path = options.profile_path();
            let (mut diagnostics, index) = profile::check(&options.root, &profile_path);
            if let Some(index) = index {
                diagnostics.extend(fixtures::check(
                    &options.root,
                    &options.fixtures_path(&index.profile_id),
                    &index,
                ));
            }
            diagnostics.sort_deterministically();
            diagnostics
        }
        Command::WorkspaceCheck => workspace::check(&options.root),
        Command::PolicyCheck => {
            let profile_path = options.profile_path();
            let (mut diagnostics, index) = profile::check(&options.root, &profile_path);
            if let Some(index) = index {
                diagnostics.extend(policy::check(
                    &options.root,
                    &options.fixtures_path(&index.profile_id),
                    &index,
                ));
            }
            diagnostics.sort_deterministically();
            diagnostics
        }
        Command::ExternalAcceptance => {
            let profile_path = options.profile_path();
            let (mut diagnostics, index) = profile::check(&options.root, &profile_path);
            if let Some(index) = index {
                diagnostics.extend(external_acceptance::check(
                    &options.root,
                    &options.external_acceptance_manifest_path(&index.profile_id),
                    &profile_path,
                    &index,
                ));
            }
            diagnostics.sort_deterministically();
            diagnostics
        }
        Command::HttpAcceptance => http_acceptance::check(
            &options.root,
            &options.profile_path(),
            &options.fixtures_path("jmeter-5.6.3"),
            options.http_acceptance_check,
        ),
        Command::GuiAcceptanceCheck => {
            let profile_path = options.profile_path();
            let (mut diagnostics, index) = profile::check(&options.root, &profile_path);
            if let Some(index) = index {
                diagnostics.extend(gui_acceptance::check(
                    &options.root,
                    &options.fixtures_path(&index.profile_id),
                    &index,
                    &profile_path,
                ));
            }
            diagnostics.sort_deterministically();
            diagnostics
        }
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
