// SPDX-License-Identifier: Apache-2.0
//! The bounded Apache JMeter 5.6.3 command-line and application boundary.
//!
//! Parsing and configuration planning are deterministic and side-effect free;
//! the explicit runner adapter then loads only allowlisted files, initializes
//! bounded native logging/reporting, and invokes the current local runtime
//! APIs. GUI, JVM, plugin, and RMI execution remain typed capability errors
//! because they are outside the bounded native local/report adapter for the
//! active `jmeter-5.6.3` profile.

#![forbid(unsafe_code)]

mod builtin_factories;
mod config;
mod current_thread_executor;
mod http_worker;
mod jtl_sink;
mod native_http_plan;
mod native_http_run;
mod native_v2_request;
mod native_v2_sampler;
mod report_input;
mod report_policy;
mod run_transaction;
mod runner;
mod time_driver;

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::{Component, Path, PathBuf};

use jmeter_rs_runtime::{Digest32, ProfileIdentity, RuntimeCapabilitySet, VersionedCapability};

#[cfg(all(test, unix))]
use std::os::unix::ffi::OsStringExt;

/// The Apache JMeter release whose command-line vocabulary this crate models.
pub const JMETER_COMPATIBILITY_VERSION: &str = "5.6.3";

/// The release profile used by the command-line boundary.
pub const JMETER_COMPATIBILITY_PROFILE: &str = "jmeter-5.6.3";

/// The checked-in Decision 0009 capability projection consumed by the
/// application-owned standalone admission boundary.
///
/// This is deliberately an `include_bytes!` asset.  The standalone binary
/// must not need a profile sidecar, a build script, a JMeter distribution, or
/// a Java runtime in order to inspect its native capability set.
pub const STANDALONE_CAPABILITY_SET_BYTES: &[u8] =
    include_bytes!("../../../compat/capability-sets/standalone-native.json");

/// Compatibility alias for the standalone preflight projection asset.
pub const STANDALONE_CAPABILITY_SET: &[u8] = STANDALONE_CAPABILITY_SET_BYTES;

/// The active profile bytes bound to [`STANDALONE_CAPABILITY_SET_BYTES`].
pub const JMETER_COMPATIBILITY_PROFILE_BYTES: &[u8] =
    include_bytes!("../../../compat/profiles/jmeter-5.6.3.json");

/// Compatibility alias for the standalone preflight profile asset.
pub const STANDALONE_PROFILE_BYTES: &[u8] = JMETER_COMPATIBILITY_PROFILE_BYTES;

/// Stable identity of the standalone capability projection.
pub const STANDALONE_CAPABILITY_SET_ID: &str = "standalone-native";

/// Schema/content version of the standalone capability projection.
pub const STANDALONE_CAPABILITY_SET_VERSION: u32 = 1;

/// SHA-256 of the embedded standalone capability projection.
pub const STANDALONE_CAPABILITY_SET_SHA256: [u8; 32] = [
    0x8d, 0xff, 0x09, 0xd9, 0x13, 0x6c, 0x90, 0xd8, 0x12, 0x63, 0xfa, 0xf3, 0xd9, 0x40, 0x50, 0x84,
    0x27, 0xd3, 0x3f, 0xef, 0x22, 0x61, 0x35, 0xce, 0x3c, 0x35, 0xe9, 0xff, 0xfc, 0x7a, 0x64, 0xe0,
];

/// SHA-256 of the embedded Apache JMeter 5.6.3 profile.
pub const JMETER_COMPATIBILITY_PROFILE_SHA256: [u8; 32] = [
    0x94, 0x99, 0x03, 0xe1, 0xa4, 0x19, 0x88, 0x06, 0xab, 0x90, 0xfa, 0x61, 0x3e, 0xee, 0x1c, 0xe6,
    0xe5, 0x50, 0xbf, 0x50, 0xfc, 0x05, 0x77, 0x61, 0x99, 0x65, 0x0f, 0x65, 0x3d, 0x82, 0x64, 0x68,
];

/// Runtime-selectable native capabilities declared by the standalone
/// projection.  `native.test-fixtures@1` is intentionally excluded because
/// it is evidence infrastructure, not an executable application capability.
pub const STANDALONE_NATIVE_CAPABILITIES: &[(&str, u32)] = &[
    ("cli.configuration", 1),
    ("config.properties", 1),
    ("expression.bounded", 1),
    ("http.contract", 1),
    ("jmx.semantic", 1),
    ("jtl.csv", 1),
    ("jtl.xml", 1),
    ("results.reporting", 1),
    ("runtime.bounded-adapters", 1),
    ("runtime.local-plan", 1),
];

/// Projection path IDs paired with their standalone capability IDs.
pub const STANDALONE_NATIVE_PATHS: &[(&str, &str, u32)] = &[
    ("native.cli.configuration", "cli.configuration", 1),
    ("native.config.properties", "config.properties", 1),
    ("native.expr.bounded", "expression.bounded", 1),
    ("native.http.contract", "http.contract", 1),
    ("native.jmx.semantic", "jmx.semantic", 1),
    ("native.jtl.csv", "jtl.csv", 1),
    ("native.jtl.xml", "jtl.xml", 1),
    ("native.results.reporting", "results.reporting", 1),
    ("native.runtime.adapters", "runtime.bounded-adapters", 1),
    ("native.runtime.local-plan", "runtime.local-plan", 1),
];

/// Hexadecimal identity of [`STANDALONE_CAPABILITY_SET_BYTES`].
pub const STANDALONE_CAPABILITY_SET_SHA256_HEX: &str =
    "8dff09d9136c90d81263faf3d940508427d33fef226135ce3c35e9fffc7a64e0";

/// Hexadecimal identity of [`JMETER_COMPATIBILITY_PROFILE_BYTES`].
pub const JMETER_COMPATIBILITY_PROFILE_SHA256_HEX: &str =
    "949903e1a4198806ab90fa613eee1ce6e550bf50fc05776199650f653d826468";

/// Schema/content version of the embedded active compatibility profile.
pub const JMETER_COMPATIBILITY_PROFILE_VERSION: u32 = 2;

/// A stable failure while validating the checked-in standalone projection.
///
/// The application validates the projection and its parent profile before
/// handing an identity to the runner or whole-plan preflight.  A malformed,
/// replaced, or mismatched asset therefore fails closed instead of silently
/// selecting a different capability set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StandaloneManifestError {
    /// An embedded asset is not valid UTF-8 JSON text.
    InvalidUtf8 {
        /// Human-readable embedded asset name.
        asset: &'static str,
    },
    /// An embedded asset does not match its pinned digest.
    DigestMismatch {
        /// Human-readable embedded asset name.
        asset: &'static str,
    },
    /// An expected stable projection/profile field is absent.
    MissingMarker {
        /// Human-readable embedded asset name.
        asset: &'static str,
        /// Stable JSON marker that was expected.
        marker: &'static str,
    },
    /// A native capability declaration is absent from the projection.
    MissingNativeCapability {
        /// Capability identifier that was expected.
        capability: &'static str,
        /// Capability declaration version that was expected.
        version: u32,
    },
    /// The active profile identity cannot be constructed.
    ProfileIdentity(jmeter_rs_runtime::CapabilityIdentityError),
    /// A native capability identity cannot be constructed.
    CapabilityIdentity {
        /// Capability identifier being validated.
        capability: &'static str,
        /// Underlying bounded runtime identity error.
        source: jmeter_rs_runtime::CapabilityIdentityError,
    },
    /// The complete runtime capability set cannot be constructed.
    CapabilitySetIdentity(jmeter_rs_runtime::CapabilityIdentityError),
}

impl StandaloneManifestError {
    /// Returns a stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidUtf8 { .. } => "capability.manifest.encoding",
            Self::DigestMismatch { .. } => "capability.manifest.digest",
            Self::MissingMarker { .. } | Self::MissingNativeCapability { .. } => {
                "capability.manifest.invalid"
            }
            Self::ProfileIdentity(_) => "capability.profile.invalid",
            Self::CapabilityIdentity { .. } => "capability.native.invalid",
            Self::CapabilitySetIdentity(_) => "capability.set.invalid",
        }
    }

    /// Returns the process classification for a rejected projection.
    #[must_use]
    pub const fn exit_class(&self) -> ExitClass {
        ExitClass::UnsupportedCapability
    }

    /// Returns the process status for a rejected projection.
    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        self.exit_class().exit_code()
    }
}

impl fmt::Display for StandaloneManifestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUtf8 { asset } | Self::DigestMismatch { asset } => {
                write!(formatter, "{}: {asset}", self.code())
            }
            Self::MissingMarker { asset, marker } => {
                write!(formatter, "{}: {asset} missing {marker}", self.code())
            }
            Self::MissingNativeCapability {
                capability,
                version,
            } => write!(formatter, "{}: native.{capability}@{version}", self.code()),
            Self::ProfileIdentity(error) | Self::CapabilitySetIdentity(error) => {
                write!(formatter, "{}: {error}", self.code())
            }
            Self::CapabilityIdentity { capability, source } => {
                write!(formatter, "{}: native.{capability}: {source}", self.code())
            }
        }
    }
}

impl std::error::Error for StandaloneManifestError {}

/// The validated identity consumed by standalone runner/preflight code.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StandaloneManifestIdentity {
    /// Stable capability-set identifier.
    pub capability_set_id: &'static str,
    /// Capability-set schema/content version.
    pub capability_set_version: u32,
    /// Exact active compatibility profile identity.
    pub profile: ProfileIdentity,
    /// Digest of the checked-in projection bytes.
    pub capability_set_digest: Digest32,
}

impl StandaloneManifestIdentity {
    /// Returns the projection digest as a fixed-size value.
    #[must_use]
    pub const fn capability_set_digest(&self) -> Digest32 {
        self.capability_set_digest
    }

    /// Returns the exact active profile identity.
    #[must_use]
    pub const fn profile(&self) -> &ProfileIdentity {
        &self.profile
    }
}

/// Returns the embedded standalone projection without consulting the
/// filesystem or environment.
#[must_use]
pub const fn standalone_capability_set_bytes() -> &'static [u8] {
    STANDALONE_CAPABILITY_SET_BYTES
}

/// Returns the embedded active profile without consulting the filesystem or
/// environment.
#[must_use]
pub const fn compatibility_profile_bytes() -> &'static [u8] {
    JMETER_COMPATIBILITY_PROFILE_BYTES
}

/// Returns the digest of the embedded standalone projection bytes.
#[must_use]
pub fn standalone_capability_set_digest() -> Digest32 {
    Digest32::from_bytes(sha256_bytes(STANDALONE_CAPABILITY_SET_BYTES))
}

/// Returns the digest of the embedded active profile bytes.
#[must_use]
pub fn compatibility_profile_digest() -> Digest32 {
    Digest32::from_bytes(sha256_bytes(JMETER_COMPATIBILITY_PROFILE_BYTES))
}

/// Validates and returns the checked-in standalone projection identity.
///
/// This performs no I/O.  Both assets are compile-time embedded, and their
/// exact bytes, parent relationship, Decision 0009 constraints, and native
/// capability declarations are checked before an identity is returned.
pub fn standalone_manifest_identity() -> Result<StandaloneManifestIdentity, StandaloneManifestError>
{
    let projection = std::str::from_utf8(STANDALONE_CAPABILITY_SET_BYTES).map_err(|_| {
        StandaloneManifestError::InvalidUtf8 {
            asset: "standalone capability projection",
        }
    })?;
    let profile = std::str::from_utf8(JMETER_COMPATIBILITY_PROFILE_BYTES).map_err(|_| {
        StandaloneManifestError::InvalidUtf8 {
            asset: "jmeter compatibility profile",
        }
    })?;

    if standalone_capability_set_digest().as_bytes() != STANDALONE_CAPABILITY_SET_SHA256 {
        return Err(StandaloneManifestError::DigestMismatch {
            asset: "standalone capability projection",
        });
    }
    if compatibility_profile_digest().as_bytes() != JMETER_COMPATIBILITY_PROFILE_SHA256 {
        return Err(StandaloneManifestError::DigestMismatch {
            asset: "jmeter compatibility profile",
        });
    }

    for marker in [
        "\"schema_id\": \"jmeter-rs.capability-set-projection\"",
        "\"schema_version\": 1",
        "\"capability_set_id\": \"standalone-native\"",
        "\"capability_set_version\": 1",
        "\"id\": \"0009\"",
        "\"include_bytes_compatible\": true",
        "\"build_script_required\": false",
        "\"unknown_fields\": \"reject\"",
        "\"java_runtime_required\": false",
        "\"jmeter_distribution_required\": false",
        "\"helper_executable_required\": false",
        "\"implicit_java_discovery\": false",
        "\"implicit_fallback\": false",
        "\"sha256\": \"949903e1a4198806ab90fa613eee1ce6e550bf50fc05776199650f653d826468\"",
    ] {
        if !projection.contains(marker) {
            return Err(StandaloneManifestError::MissingMarker {
                asset: "standalone capability projection",
                marker,
            });
        }
    }
    for marker in [
        "\"schema_id\": \"jmeter-rs.compatibility-profile\"",
        "\"profile_id\": \"jmeter-5.6.3\"",
        "\"profile_version\": 2",
        "\"source_commit\": \"34a2785748e9e0b14702595e8682c387869deda3\"",
    ] {
        if !profile.contains(marker) {
            return Err(StandaloneManifestError::MissingMarker {
                asset: "jmeter compatibility profile",
                marker,
            });
        }
    }
    for &(path_id, capability, version) in STANDALONE_NATIVE_PATHS {
        let path_marker = format!("\"path_id\": \"{path_id}@{version}\"");
        let id_marker = format!("\"capability_id\": \"{capability}\"");
        if !projection.contains(path_marker.as_str()) || !projection.contains(id_marker.as_str()) {
            return Err(StandaloneManifestError::MissingNativeCapability {
                capability,
                version,
            });
        }
    }

    let profile_identity = ProfileIdentity::new(
        JMETER_COMPATIBILITY_PROFILE,
        JMETER_COMPATIBILITY_PROFILE_VERSION,
        Digest32::from_bytes(JMETER_COMPATIBILITY_PROFILE_SHA256),
    )
    .map_err(StandaloneManifestError::ProfileIdentity)?;
    Ok(StandaloneManifestIdentity {
        capability_set_id: STANDALONE_CAPABILITY_SET_ID,
        capability_set_version: STANDALONE_CAPABILITY_SET_VERSION,
        profile: profile_identity,
        capability_set_digest: Digest32::from_bytes(STANDALONE_CAPABILITY_SET_SHA256),
    })
}

/// Alias used by callers that phrase validation as an explicit operation.
pub fn validate_standalone_manifest() -> Result<StandaloneManifestIdentity, StandaloneManifestError>
{
    standalone_manifest_identity()
}

/// Builds the no-Java standalone runtime capability set for one executable
/// plan digest.  The caller must still classify the complete implementation
/// path manifest with [`RuntimeCapabilitySet::admit`] before setup.
pub fn standalone_runtime_capability_set(
    plan_digest: Digest32,
) -> Result<RuntimeCapabilitySet, StandaloneManifestError> {
    let identity = standalone_manifest_identity()?;
    let capabilities = STANDALONE_NATIVE_CAPABILITIES
        .iter()
        .map(|&(capability, version)| {
            VersionedCapability::new(capability, version).map_err(|source| {
                StandaloneManifestError::CapabilityIdentity { capability, source }
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    RuntimeCapabilitySet::standalone_native(
        identity.profile,
        plan_digest,
        identity.capability_set_digest,
        capabilities,
    )
    .map_err(StandaloneManifestError::CapabilitySetIdentity)
}

/// Alias for the explicit native capability-set constructor.
pub fn standalone_native_capability_set(
    plan_digest: Digest32,
) -> Result<RuntimeCapabilitySet, StandaloneManifestError> {
    standalone_runtime_capability_set(plan_digest)
}

// SHA-256 is kept local so the standalone application does not acquire a
// crypto/native dependency solely to authenticate its checked-in assets.
// This is the FIPS 180-4 padded, big-endian 512-bit block construction.
fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut state = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];
    let mut block = [0_u8; 64];
    let mut used = 0_usize;
    for byte in bytes {
        block[used] = *byte;
        used += 1;
        if used == block.len() {
            sha256_compress(&mut state, &block);
            used = 0;
        }
    }

    block[used] = 0x80;
    used += 1;
    if used > 56 {
        block[used..].fill(0);
        sha256_compress(&mut state, &block);
        block.fill(0);
    } else {
        block[used..56].fill(0);
    }
    let bit_len = (bytes.len() as u64).wrapping_mul(8);
    block[56..].copy_from_slice(&bit_len.to_be_bytes());
    sha256_compress(&mut state, &block);

    let mut digest = [0_u8; 32];
    for (index, word) in state.into_iter().enumerate() {
        digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    digest
}

#[allow(
    clippy::many_single_char_names,
    reason = "SHA-256 compression notation follows the standard"
)]
fn sha256_compress(state: &mut [u32; 8], block: &[u8; 64]) {
    const ROUND_CONSTANTS: [u32; 64] = [
        0x428a_2f98,
        0x7137_4491,
        0xb5c0_fbcf,
        0xe9b5_dba5,
        0x3956_c25b,
        0x59f1_11f1,
        0x923f_82a4,
        0xab1c_5ed5,
        0xd807_aa98,
        0x1283_5b01,
        0x2431_85be,
        0x550c_7dc3,
        0x72be_5d74,
        0x80de_b1fe,
        0x9bdc_06a7,
        0xc19b_f174,
        0xe49b_69c1,
        0xefbe_4786,
        0x0fc1_9dc6,
        0x240c_a1cc,
        0x2de9_2c6f,
        0x4a74_84aa,
        0x5cb0_a9dc,
        0x76f9_88da,
        0x983e_5152,
        0xa831_c66d,
        0xb003_27c8,
        0xbf59_7fc7,
        0xc6e0_0bf3,
        0xd5a7_9147,
        0x06ca_6351,
        0x1429_2967,
        0x27b7_0a85,
        0x2e1b_2138,
        0x4d2c_6dfc,
        0x5338_0d13,
        0x650a_7354,
        0x766a_0abb,
        0x81c2_c92e,
        0x9272_2c85,
        0xa2bf_e8a1,
        0xa81a_664b,
        0xc24b_8b70,
        0xc76c_51a3,
        0xd192_e819,
        0xd699_0624,
        0xf40e_3585,
        0x106a_a070,
        0x19a4_c116,
        0x1e37_6c08,
        0x2748_774c,
        0x34b0_bcb5,
        0x391c_0cb3,
        0x4ed8_aa4a,
        0x5b9c_ca4f,
        0x682e_6ff3,
        0x748f_82ee,
        0x78a5_636f,
        0x84c8_7814,
        0x8cc7_0208,
        0x90be_fffa,
        0xa450_6ceb,
        0xbef9_a3f7,
        0xc671_78f2,
    ];
    let mut schedule = [0_u32; 64];
    for (index, word) in schedule.iter_mut().enumerate().take(16) {
        let offset = index * 4;
        *word = u32::from_be_bytes([
            block[offset],
            block[offset + 1],
            block[offset + 2],
            block[offset + 3],
        ]);
    }
    for index in 16..64 {
        let lower = schedule[index - 15];
        let upper = schedule[index - 2];
        let sigma0 = lower.rotate_right(7) ^ lower.rotate_right(18) ^ (lower >> 3);
        let sigma1 = upper.rotate_right(17) ^ upper.rotate_right(19) ^ (upper >> 10);
        schedule[index] = schedule[index - 16]
            .wrapping_add(sigma0)
            .wrapping_add(schedule[index - 7])
            .wrapping_add(sigma1);
    }

    let mut working = *state;
    for index in 0..64 {
        let [a, b, c, d, e, f, g, h] = working;
        let sigma1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let choose = (e & f) ^ ((!e) & g);
        let temporary1 = h
            .wrapping_add(sigma1)
            .wrapping_add(choose)
            .wrapping_add(ROUND_CONSTANTS[index])
            .wrapping_add(schedule[index]);
        let sigma0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let majority = (a & b) ^ (a & c) ^ (b & c);
        let temporary2 = sigma0.wrapping_add(majority);
        working = [
            temporary1.wrapping_add(temporary2),
            a,
            b,
            c,
            d.wrapping_add(temporary1),
            e,
            f,
            g,
        ];
    }
    for (state_word, working_word) in state.iter_mut().zip(working) {
        *state_word = state_word.wrapping_add(working_word);
    }
}

pub use config::{
    ConfigError, ConfigFileNames, ConfigFsPolicy, ConfigLimits, ConfigLoader, ConfigNamespace,
    ConfigPlan, ConfigSource, ConfigWarning, DecodeMode, JavaString, LoggingConfig,
    LoggingDirective, PropertyMap, PropertyOperation, PropertyOperationKind, PropertyProvenance,
    PropertyValue, RemovalProvenance, ResolvedConfig, ResolvedProperty, SymlinkPolicy,
};
pub use runner::{
    ENVIRONMENT_ALLOWLIST, EnvironmentView, LaunchEnvironment, RunCategory, RunError, RunOutcome,
    execute_invocation,
};

/// A command-line option, including its canonical short and long spellings.
///
/// The table is the single source for parsing, repeatability checks, and the
/// pinned Apache Commons CLI-compatible options rendering.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OptionSpec {
    /// Stable identity used by the parser and configuration plan.
    pub id: OptionId,
    /// Short spelling without the leading dash, if one exists.
    pub short: Option<&'static str>,
    /// Long spelling without the leading two dashes, if one exists.
    pub long: &'static str,
    /// Whether the option consumes one argument.
    pub takes_value: bool,
    /// Whether the option may occur more than once.
    pub repeatable: bool,
    /// Human-readable argument shape used by generated help.
    pub value_hint: Option<&'static str>,
    /// Concise description of the option's observable purpose.
    pub description: &'static str,
}

/// Stable identities for all documented Apache JMeter 5.6.3 options.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum OptionId {
    /// `-?`/`--?`.
    Help,
    /// `-h`/`--help`.
    HelpLong,
    /// `-v`/`--version`.
    Version,
    /// `-p`/`--propfile`.
    Propfile,
    /// `-q`/`--addprop`.
    Addprop,
    /// `-t`/`--testfile`.
    Testfile,
    /// `-l`/`--logfile`.
    Logfile,
    /// `-i`/`--jmeterlogconf`.
    Jmeterlogconf,
    /// `-j`/`--jmeterlogfile`.
    Jmeterlogfile,
    /// `-n`/`--nongui`.
    Nongui,
    /// `-s`/`--server`.
    Server,
    /// `-E`/`--proxyScheme`.
    ProxyScheme,
    /// `-H`/`--proxyHost`.
    ProxyHost,
    /// `-P`/`--proxyPort`.
    ProxyPort,
    /// `-N`/`--nonProxyHosts`.
    NonProxyHosts,
    /// `-u`/`--username`.
    Username,
    /// `-a`/`--password`.
    Password,
    /// `-J`/`--jmeterproperty`.
    Jmeterproperty,
    /// `-G`/`--globalproperty`.
    Globalproperty,
    /// `-D`/`--systemproperty`.
    Systemproperty,
    /// `-S`/`--systemPropertyFile`.
    SystemPropertyFile,
    /// `-f`/`--forceDeleteResultFile`.
    ForceDeleteResultFile,
    /// `-L`/`--loglevel`.
    Loglevel,
    /// `-r`/`--runremote`.
    Runremote,
    /// `-R`/`--remotestart`.
    Remotestart,
    /// `-d`/`--homedir`.
    Homedir,
    /// `-X`/`--remoteexit`.
    Remoteexit,
    /// `-g`/`--reportonly`.
    Reportonly,
    /// `-e`/`--reportatendofloadtests`.
    Reportatendofloadtests,
    /// `-o`/`--reportoutputfolder`.
    Reportoutputfolder,
}

impl OptionId {
    /// Returns the canonical short spelling, without a leading dash.
    #[must_use]
    pub const fn short(self) -> Option<&'static str> {
        option_spec(self).short
    }

    /// Returns the canonical long spelling, without leading dashes.
    #[must_use]
    pub const fn long(self) -> &'static str {
        option_spec(self).long
    }

    /// Returns the canonical display name, preferring the short spelling.
    #[must_use]
    pub const fn display_name(self) -> &'static str {
        match self.short() {
            Some(short) => short,
            None => self.long(),
        }
    }

    /// Returns whether this option consumes an argument.
    #[must_use]
    pub const fn takes_value(self) -> bool {
        option_spec(self).takes_value
    }

    /// Returns whether this option can be repeated.
    #[must_use]
    pub const fn repeatable(self) -> bool {
        option_spec(self).repeatable
    }
}

/// The complete documented option table in generated-help order.
pub const OPTION_TABLE: &[OptionSpec] = &[
    OptionSpec {
        id: OptionId::Help,
        short: Some("?"),
        long: "?",
        takes_value: false,
        repeatable: false,
        value_hint: None,
        description: "print command line options and exit",
    },
    OptionSpec {
        id: OptionId::HelpLong,
        short: Some("h"),
        long: "help",
        takes_value: false,
        repeatable: false,
        value_hint: None,
        description: "print usage information and exit",
    },
    OptionSpec {
        id: OptionId::Version,
        short: Some("v"),
        long: "version",
        takes_value: false,
        repeatable: false,
        value_hint: None,
        description: "print the version information and exit",
    },
    OptionSpec {
        id: OptionId::Propfile,
        short: Some("p"),
        long: "propfile",
        takes_value: true,
        repeatable: false,
        value_hint: Some("FILE"),
        description: "the jmeter property file to use",
    },
    OptionSpec {
        id: OptionId::Addprop,
        short: Some("q"),
        long: "addprop",
        takes_value: true,
        repeatable: true,
        value_hint: Some("FILE"),
        description: "additional JMeter property file(s)",
    },
    OptionSpec {
        id: OptionId::Testfile,
        short: Some("t"),
        long: "testfile",
        takes_value: true,
        repeatable: false,
        value_hint: Some("FILE|LAST"),
        description: "the jmeter test(.jmx) file to run. \"-t LAST\" will load last used file",
    },
    OptionSpec {
        id: OptionId::Logfile,
        short: Some("l"),
        long: "logfile",
        takes_value: true,
        repeatable: false,
        value_hint: Some("FILE|LAST"),
        description: "the file to log samples to",
    },
    OptionSpec {
        id: OptionId::Jmeterlogconf,
        short: Some("i"),
        long: "jmeterlogconf",
        takes_value: true,
        repeatable: false,
        value_hint: Some("FILE"),
        description: "jmeter logging configuration file (log4j2.xml)",
    },
    OptionSpec {
        id: OptionId::Jmeterlogfile,
        short: Some("j"),
        long: "jmeterlogfile",
        takes_value: true,
        repeatable: false,
        value_hint: Some("FILE|LAST"),
        description: "jmeter run log file (jmeter.log)",
    },
    OptionSpec {
        id: OptionId::Nongui,
        short: Some("n"),
        long: "nongui",
        takes_value: false,
        repeatable: false,
        value_hint: None,
        description: "run JMeter in nongui mode",
    },
    OptionSpec {
        id: OptionId::Server,
        short: Some("s"),
        long: "server",
        takes_value: false,
        repeatable: false,
        value_hint: None,
        description: "run the JMeter server",
    },
    OptionSpec {
        id: OptionId::ProxyScheme,
        short: Some("E"),
        long: "proxyScheme",
        takes_value: true,
        repeatable: false,
        value_hint: Some("SCHEME"),
        description: "Set a proxy scheme to use for the proxy server",
    },
    OptionSpec {
        id: OptionId::ProxyHost,
        short: Some("H"),
        long: "proxyHost",
        takes_value: true,
        repeatable: false,
        value_hint: Some("HOST"),
        description: "Set a proxy server for JMeter to use",
    },
    OptionSpec {
        id: OptionId::ProxyPort,
        short: Some("P"),
        long: "proxyPort",
        takes_value: true,
        repeatable: false,
        value_hint: Some("PORT"),
        description: "Set proxy server port for JMeter to use",
    },
    OptionSpec {
        id: OptionId::NonProxyHosts,
        short: Some("N"),
        long: "nonProxyHosts",
        takes_value: true,
        repeatable: false,
        value_hint: Some("PATTERNS"),
        description: "Set nonproxy host list (e.g. *.apache.org|localhost)",
    },
    OptionSpec {
        id: OptionId::Username,
        short: Some("u"),
        long: "username",
        takes_value: true,
        repeatable: false,
        value_hint: Some("USER"),
        description: "Set username for proxy server that JMeter is to use",
    },
    OptionSpec {
        id: OptionId::Password,
        short: Some("a"),
        long: "password",
        takes_value: true,
        repeatable: false,
        value_hint: Some("PASSWORD"),
        description: "Set password for proxy server that JMeter is to use",
    },
    OptionSpec {
        id: OptionId::Jmeterproperty,
        short: Some("J"),
        long: "jmeterproperty",
        takes_value: true,
        repeatable: true,
        value_hint: Some("KEY=VALUE"),
        description: "Define additional JMeter properties",
    },
    OptionSpec {
        id: OptionId::Globalproperty,
        short: Some("G"),
        long: "globalproperty",
        takes_value: true,
        repeatable: true,
        value_hint: Some("KEY=VALUE|FILE"),
        description: "Define Global properties (sent to servers)\n\t\te.g. -Gport=123 or -Gglobal.properties",
    },
    OptionSpec {
        id: OptionId::Systemproperty,
        short: Some("D"),
        long: "systemproperty",
        takes_value: true,
        repeatable: true,
        value_hint: Some("KEY=VALUE"),
        description: "Define additional system properties",
    },
    OptionSpec {
        id: OptionId::SystemPropertyFile,
        short: Some("S"),
        long: "systemPropertyFile",
        takes_value: true,
        repeatable: true,
        value_hint: Some("FILE"),
        description: "additional system property file(s)",
    },
    OptionSpec {
        id: OptionId::ForceDeleteResultFile,
        short: Some("f"),
        long: "forceDeleteResultFile",
        takes_value: false,
        repeatable: false,
        value_hint: None,
        description: "force delete existing results files and web report folder if present before starting the test",
    },
    OptionSpec {
        id: OptionId::Loglevel,
        short: Some("L"),
        long: "loglevel",
        takes_value: true,
        repeatable: true,
        value_hint: Some("[CATEGORY=]LEVEL"),
        description: "[category=]level e.g. jorphan=INFO, jmeter.util=DEBUG or com.example.foo=WARN",
    },
    OptionSpec {
        id: OptionId::Runremote,
        short: Some("r"),
        long: "runremote",
        takes_value: false,
        repeatable: false,
        value_hint: None,
        description: "Start remote servers (as defined in remote_hosts)",
    },
    OptionSpec {
        id: OptionId::Remotestart,
        short: Some("R"),
        long: "remotestart",
        takes_value: true,
        repeatable: false,
        value_hint: Some("HOSTS"),
        description: "Start these remote servers (overrides remote_hosts)",
    },
    OptionSpec {
        id: OptionId::Homedir,
        short: Some("d"),
        long: "homedir",
        takes_value: true,
        repeatable: false,
        value_hint: Some("DIR"),
        description: "the jmeter home directory to use",
    },
    OptionSpec {
        id: OptionId::Remoteexit,
        short: Some("X"),
        long: "remoteexit",
        takes_value: false,
        repeatable: false,
        value_hint: None,
        description: "Exit the remote servers at end of test (non-GUI)",
    },
    OptionSpec {
        id: OptionId::Reportonly,
        short: Some("g"),
        long: "reportonly",
        takes_value: true,
        repeatable: false,
        value_hint: Some("JTL"),
        description: "generate report dashboard only, from a test results file",
    },
    OptionSpec {
        id: OptionId::Reportatendofloadtests,
        short: Some("e"),
        long: "reportatendofloadtests",
        takes_value: false,
        repeatable: false,
        value_hint: None,
        description: "generate report dashboard after load test",
    },
    OptionSpec {
        id: OptionId::Reportoutputfolder,
        short: Some("o"),
        long: "reportoutputfolder",
        takes_value: true,
        repeatable: false,
        value_hint: Some("DIR"),
        description: "output folder for report dashboard",
    },
];

/// Returns the complete option table.
#[must_use]
pub const fn option_table() -> &'static [OptionSpec] {
    OPTION_TABLE
}

const fn option_spec(id: OptionId) -> OptionSpec {
    match id {
        OptionId::Help => OPTION_TABLE[0],
        OptionId::HelpLong => OPTION_TABLE[1],
        OptionId::Version => OPTION_TABLE[2],
        OptionId::Propfile => OPTION_TABLE[3],
        OptionId::Addprop => OPTION_TABLE[4],
        OptionId::Testfile => OPTION_TABLE[5],
        OptionId::Logfile => OPTION_TABLE[6],
        OptionId::Jmeterlogconf => OPTION_TABLE[7],
        OptionId::Jmeterlogfile => OPTION_TABLE[8],
        OptionId::Nongui => OPTION_TABLE[9],
        OptionId::Server => OPTION_TABLE[10],
        OptionId::ProxyScheme => OPTION_TABLE[11],
        OptionId::ProxyHost => OPTION_TABLE[12],
        OptionId::ProxyPort => OPTION_TABLE[13],
        OptionId::NonProxyHosts => OPTION_TABLE[14],
        OptionId::Username => OPTION_TABLE[15],
        OptionId::Password => OPTION_TABLE[16],
        OptionId::Jmeterproperty => OPTION_TABLE[17],
        OptionId::Globalproperty => OPTION_TABLE[18],
        OptionId::Systemproperty => OPTION_TABLE[19],
        OptionId::SystemPropertyFile => OPTION_TABLE[20],
        OptionId::ForceDeleteResultFile => OPTION_TABLE[21],
        OptionId::Loglevel => OPTION_TABLE[22],
        OptionId::Runremote => OPTION_TABLE[23],
        OptionId::Remotestart => OPTION_TABLE[24],
        OptionId::Homedir => OPTION_TABLE[25],
        OptionId::Remoteexit => OPTION_TABLE[26],
        OptionId::Reportonly => OPTION_TABLE[27],
        OptionId::Reportatendofloadtests => OPTION_TABLE[28],
        OptionId::Reportoutputfolder => OPTION_TABLE[29],
    }
}

/// The mode selected by the parsed options.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunMode {
    /// No mode flag was supplied; this is JMeter's GUI/default mode.
    Gui,
    /// `-n`/`--nongui` was supplied.
    NonGui,
    /// `-s`/`--server` was supplied.
    Server,
    /// `-g`/`--reportonly` was supplied.
    ReportOnly,
}

impl RunMode {
    /// Returns the stable mode label used in diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Gui => "gui",
            Self::NonGui => "non-gui",
            Self::Server => "server",
            Self::ReportOnly => "report-only",
        }
    }
}

impl fmt::Display for RunMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The parser's top-level action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    /// Parse and print the pinned option catalog (`-?`), then succeed.
    Options,
    /// Parse and print the pinned help resource (`-h`), then succeed.
    Help,
    /// Parse and print version information, then succeed.
    Version,
    /// Continue to a process/engine adapter.
    Execute,
}

/// Compatibility alias for callers that prefer `CliAction` terminology.
pub type CliAction = Action;

/// Stable process exit classes used by the binary and process adapters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExitClass {
    /// The requested non-execution action completed successfully.
    Success,
    /// The engine completed and recorded one or more failed samples.
    SampleFailure,
    /// The command line grammar or option combination was invalid.
    UsageError,
    /// A valid command could not be configured without performing execution.
    ConfigurationError,
    /// The selected capability lies outside the bounded native local/report
    /// adapter for the active compatibility profile.
    UnsupportedCapability,
    /// A fatal startup, local runtime, or report operation failed.
    Fatal,
    /// A remote adapter failed or remains unavailable.
    RemoteFailure,
    /// An unexpected internal invariant failed.
    InternalError,
}

impl ExitClass {
    /// Returns a stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Success => "ok",
            Self::SampleFailure => "sample.failure",
            Self::UsageError => "cli.usage",
            Self::ConfigurationError => "config.invalid",
            Self::UnsupportedCapability => "capability.unavailable",
            Self::Fatal => "fatal",
            Self::RemoteFailure => "remote.failure",
            Self::InternalError => "internal.error",
        }
    }

    /// Returns the conventional process status for this class.
    #[must_use]
    pub const fn exit_code(self) -> u8 {
        match self {
            Self::Success => 0,
            Self::SampleFailure => 0,
            Self::UsageError => 2,
            Self::ConfigurationError => 78,
            Self::UnsupportedCapability => 78,
            Self::Fatal => 1,
            Self::RemoteFailure => 1,
            Self::InternalError => 70,
        }
    }
}

impl fmt::Display for ExitClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

/// A parser or semantic-validation error with a stable category.
#[derive(Clone, Eq, PartialEq)]
pub enum CliError {
    /// An option that requires an argument was not followed by one.
    MissingValue {
        /// Option identity.
        option: OptionId,
        /// Exact spelling supplied by the caller.
        spelling: String,
    },
    /// An option spelling is not in [`OPTION_TABLE`].
    UnknownOption {
        /// Exact token supplied by the caller.
        token: String,
    },
    /// A positional token was left after option processing.
    UnexpectedArgument {
        /// Exact token supplied by the caller.
        argument: String,
    },
    /// A singleton option appeared more than once.
    DuplicateOption {
        /// Option identity.
        option: OptionId,
        /// Exact spelling of the duplicate occurrence.
        spelling: String,
    },
    /// A boolean option was written with an argument.
    UnexpectedValue {
        /// Option identity.
        option: OptionId,
        /// Exact spelling supplied by the caller.
        spelling: String,
    },
    /// A key/value or logging-level value was malformed.
    InvalidValue {
        /// Option identity.
        option: OptionId,
        /// Value (redacted when the option is the proxy password).
        value: String,
        /// Stable reason identifier.
        reason: ValueError,
    },
    /// Two or more otherwise valid options cannot be used together.
    IncompatibleOptions {
        /// Stable option identities in encounter order.
        options: Vec<OptionId>,
        /// Concise diagnostic reason.
        reason: CombinationError,
    },
    /// An input argument could not be represented as UTF-8 by the safe parser.
    NonUnicodeArgument,
    /// An internal table invariant was violated.
    InvalidOptionTable,
}

/// Stable reasons for malformed option values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValueError {
    /// A required value was empty.
    Empty,
    /// A property assignment did not contain a non-empty key and `=`.
    MissingAssignment,
    /// A logging level did not contain a non-empty level.
    MissingLogLevel,
    /// A path-like value cannot be empty.
    EmptyPath,
}

impl ValueError {
    /// Stable reason code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::MissingAssignment => "missing-assignment",
            Self::MissingLogLevel => "missing-log-level",
            Self::EmptyPath => "empty-path",
        }
    }
}

impl fmt::Display for ValueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

/// Stable reasons for invalid option combinations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CombinationError {
    /// `-n` needs a plan (except for report-only, which is a different mode).
    NonGuiNeedsTestfile,
    /// `-e` needs a result file.
    ReportAtEndNeedsLogfile,
    /// Report generation after a load test is only meaningful in non-GUI mode.
    ReportAtEndNeedsNonGui,
    /// `-g` and ordinary load-test mode cannot be combined.
    ReportOnlyConflict,
    /// Report-only mode cannot receive a test plan.
    ReportOnlyNeedsOnlyJtl,
    /// Report output has no report-generation source.
    ReportOutputNeedsReport,
    /// Remote flags require a local CLI load test.
    RemoteNeedsNonGui,
    /// Server mode cannot be combined with a local test run.
    ServerConflict,
    /// GUI/server/report-only/non-GUI are mutually exclusive mode selectors.
    MultipleModes,
    /// A proxy host and port must be supplied together.
    ProxyNeedsHostAndPort,
}

impl CombinationError {
    /// Stable reason code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NonGuiNeedsTestfile => "nongui-needs-testfile",
            Self::ReportAtEndNeedsLogfile => "report-at-end-needs-logfile",
            Self::ReportAtEndNeedsNonGui => "report-at-end-needs-nongui",
            Self::ReportOnlyConflict => "report-only-conflict",
            Self::ReportOnlyNeedsOnlyJtl => "report-only-needs-only-jtl",
            Self::ReportOutputNeedsReport => "report-output-needs-report",
            Self::RemoteNeedsNonGui => "remote-needs-nongui",
            Self::ServerConflict => "server-conflict",
            Self::MultipleModes => "multiple-modes",
            Self::ProxyNeedsHostAndPort => "proxy-needs-host-and-port",
        }
    }
}

impl fmt::Display for CombinationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl CliError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::MissingValue { .. } => "cli.missing-value",
            Self::UnknownOption { .. } => "cli.unknown-option",
            Self::UnexpectedArgument { .. } => "cli.unexpected-argument",
            Self::DuplicateOption { .. } => "cli.duplicate-option",
            Self::UnexpectedValue { .. } => "cli.unexpected-value",
            Self::InvalidValue { .. } => "cli.invalid-value",
            Self::IncompatibleOptions { .. } => "cli.incompatible-options",
            Self::NonUnicodeArgument => "cli.non-unicode-argument",
            Self::InvalidOptionTable => "internal.invalid-option-table",
        }
    }

    /// Returns the stable process exit class for this error.
    #[must_use]
    pub const fn exit_class(&self) -> ExitClass {
        match self {
            Self::InvalidOptionTable => ExitClass::InternalError,
            _ => ExitClass::UsageError,
        }
    }

    /// Returns the conventional process exit status for this error.
    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        self.exit_class().exit_code()
    }
}

impl fmt::Debug for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingValue { option, spelling } => formatter
                .debug_struct("MissingValue")
                .field("option", option)
                .field("spelling", &redact_option_spelling(*option, spelling))
                .finish(),
            Self::UnknownOption { token } => formatter
                .debug_struct("UnknownOption")
                .field("token", &redact_cli_token(token))
                .finish(),
            Self::UnexpectedArgument { argument } => formatter
                .debug_struct("UnexpectedArgument")
                .field("argument", &redact_cli_token(argument))
                .finish(),
            Self::DuplicateOption { option, spelling } => formatter
                .debug_struct("DuplicateOption")
                .field("option", option)
                .field("spelling", &redact_option_spelling(*option, spelling))
                .finish(),
            Self::UnexpectedValue { option, spelling } => formatter
                .debug_struct("UnexpectedValue")
                .field("option", option)
                .field("spelling", &redact_option_spelling(*option, spelling))
                .finish(),
            Self::InvalidValue {
                option,
                value,
                reason,
            } => formatter
                .debug_struct("InvalidValue")
                .field("option", option)
                .field("value", &redact_cli_value(*option, value))
                .field("reason", reason)
                .finish(),
            Self::IncompatibleOptions { options, reason } => formatter
                .debug_struct("IncompatibleOptions")
                .field("options", options)
                .field("reason", reason)
                .finish(),
            Self::NonUnicodeArgument => formatter.write_str("NonUnicodeArgument"),
            Self::InvalidOptionTable => formatter.write_str("InvalidOptionTable"),
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingValue { option, spelling } => {
                write!(
                    formatter,
                    "{} requires an argument",
                    redact_option_spelling(*option, spelling)
                )
            }
            Self::UnknownOption { token } => {
                write!(formatter, "unknown option {:?}", redact_cli_token(token))
            }
            Self::UnexpectedArgument { argument } => {
                write!(
                    formatter,
                    "unexpected argument {:?}",
                    redact_cli_token(argument)
                )
            }
            Self::DuplicateOption { option, spelling } => {
                write!(
                    formatter,
                    "option {:?} may not be repeated",
                    redact_option_spelling(*option, spelling)
                )
            }
            Self::UnexpectedValue { option, spelling } => {
                write!(
                    formatter,
                    "option {:?} does not take an argument",
                    redact_option_spelling(*option, spelling)
                )
            }
            Self::InvalidValue {
                option,
                value,
                reason,
            } => {
                if *option == OptionId::Password {
                    write!(formatter, "invalid value for --password ({reason})")
                } else {
                    write!(
                        formatter,
                        "invalid value {:?} for --{} ({reason})",
                        redact_cli_value(*option, value),
                        option.long()
                    )
                }
            }
            Self::IncompatibleOptions { options, reason } => {
                write!(formatter, "incompatible options ")?;
                for (index, option) in options.iter().enumerate() {
                    if index != 0 {
                        formatter.write_str(" and ")?;
                    }
                    write!(formatter, "--{}", option.long())?;
                }
                write!(formatter, " ({reason})")
            }
            Self::NonUnicodeArgument => formatter.write_str("an argument is not valid UTF-8"),
            Self::InvalidOptionTable => formatter.write_str("the option table is inconsistent"),
        }
    }
}

impl std::error::Error for CliError {}

/// An exact option occurrence in the order supplied by the user.
#[derive(Clone, Eq, PartialEq)]
pub struct OptionOccurrence {
    /// Stable option identity.
    pub id: OptionId,
    /// Exact option token spelling (`-J`, `--jmeterproperty`, or attached
    /// spelling's option prefix).
    pub spelling: String,
    /// Exact argument string, if present.
    pub value: Option<String>,
    /// Exact one- or two-argument payload before normalization.
    pub arguments: Vec<String>,
    /// Zero-based index of the option token in the input argument vector.
    pub index: usize,
    /// Whether the option's value is a secret and must be redacted by
    /// formatting implementations.
    pub sensitive: bool,
}

impl OptionOccurrence {
    /// Returns the actual value; formatting the occurrence never exposes it
    /// when [`Self::sensitive`] is true.
    #[must_use]
    pub fn value(&self) -> Option<&str> {
        self.value.as_deref()
    }
}

impl fmt::Debug for OptionOccurrence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sensitive = self.sensitive || occurrence_value_is_sensitive(self.id, self.value());
        let mut debug = formatter.debug_struct("OptionOccurrence");
        debug.field("id", &self.id);
        debug.field("spelling", &self.spelling);
        if sensitive {
            debug.field("value", &"<redacted>");
            debug.field("arguments", &"<redacted>");
        } else {
            debug.field("value", &self.value);
            debug.field("arguments", &self.arguments);
        }
        debug.field("index", &self.index);
        debug.field("sensitive", &self.sensitive);
        debug.finish()
    }
}

/// An exact `KEY=VALUE` assignment from `-J`, `-D`, or an equivalent source.
#[derive(Clone, Eq, PartialEq)]
pub struct PropertyAssignment {
    /// Exact key before the first equals sign.
    pub key: String,
    /// Exact value after the first equals sign; additional equals signs are
    /// retained.
    pub value: String,
    /// Exact user string, retained for diagnostics and round-tripping.
    pub raw: String,
}

impl PropertyAssignment {
    fn parse(option: OptionId, value: String) -> Result<Self, CliError> {
        let Some((key, property_value)) = value.split_once('=') else {
            return Err(CliError::InvalidValue {
                option,
                value,
                reason: ValueError::MissingAssignment,
            });
        };
        if key.is_empty() {
            return Err(CliError::InvalidValue {
                option,
                value,
                reason: ValueError::MissingAssignment,
            });
        }
        Ok(Self {
            key: key.to_owned(),
            value: property_value.to_owned(),
            raw: value,
        })
    }

    /// Returns whether this key is conventionally a proxy password property.
    #[must_use]
    pub fn is_sensitive(&self) -> bool {
        is_sensitive_key(&self.key)
    }
}

impl fmt::Debug for PropertyAssignment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("PropertyAssignment");
        debug.field("key", &self.key);
        if self.is_sensitive() {
            debug.field("value", &"<redacted>");
            debug.field("raw", &"<redacted>");
        } else {
            debug.field("value", &self.value);
            debug.field("raw", &self.raw);
        }
        debug.finish()
    }
}

impl fmt::Display for PropertyAssignment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_sensitive() {
            write!(formatter, "{}=<redacted>", self.key)
        } else {
            formatter.write_str(&self.raw)
        }
    }
}

/// A `-G`/`--globalproperty` value, which can be an assignment or a file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GlobalProperty {
    /// A global key/value assignment.
    Assignment(PropertyAssignment),
    /// A properties file path, retained without filesystem access.
    File {
        /// Exact user path.
        path: String,
    },
}

impl GlobalProperty {
    fn parse(value: String) -> Result<Self, CliError> {
        if value.is_empty() {
            return Err(CliError::InvalidValue {
                option: OptionId::Globalproperty,
                value,
                reason: ValueError::Empty,
            });
        }
        // The Java launcher distinguishes a non-empty assignment from the
        // file form by the RHS.  Thus `-Gfoo=` names a property file `foo`;
        // the separator is grammar, not part of the file name.
        let assignment_value_is_nonempty = value
            .split_once('=')
            .is_some_and(|(_, property_value)| !property_value.is_empty());
        if assignment_value_is_nonempty {
            PropertyAssignment::parse(OptionId::Globalproperty, value).map(Self::Assignment)
        } else {
            let path = value
                .split_once('=')
                .map_or(value.as_str(), |(path, _)| path)
                .to_owned();
            if path.is_empty() {
                return Err(CliError::InvalidValue {
                    option: OptionId::Globalproperty,
                    value,
                    reason: ValueError::Empty,
                });
            }
            Ok(Self::File { path })
        }
    }

    /// Returns the exact input spelling.
    #[must_use]
    pub fn raw(&self) -> &str {
        match self {
            Self::Assignment(assignment) => &assignment.raw,
            Self::File { path } => path,
        }
    }
}

/// A path-like argument and its special `LAST` interpretation.
#[derive(Clone, Eq, PartialEq)]
pub struct PathArgument {
    /// Exact user string.
    pub raw: String,
    /// Whether the value requests GUI last-plan resolution.
    pub kind: PathKind,
}

/// Special interpretation of a path argument.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathKind {
    /// The value is an ordinary path.
    Explicit,
    /// The exact token was `LAST`; resolution is deferred to an explicit
    /// persistence capability.
    Last,
    /// `-j`/`--jmeterlogfile` retains the LAST spelling for the NewDriver
    /// call-site; the source launcher does not pass it through `processLAST`.
    LastLiteral,
}

impl PathArgument {
    fn new(value: String) -> Result<Self, CliError> {
        if value.is_empty() {
            return Err(CliError::InvalidValue {
                option: OptionId::Testfile,
                value,
                reason: ValueError::EmptyPath,
            });
        }
        let kind = if value == "LAST" {
            PathKind::Last
        } else {
            PathKind::Explicit
        };
        Ok(Self { raw: value, kind })
    }

    fn new_log(value: String) -> Result<Self, CliError> {
        if value.is_empty() {
            return Err(CliError::InvalidValue {
                option: OptionId::Logfile,
                value,
                reason: ValueError::EmptyPath,
            });
        }
        let kind = if matches!(value.as_str(), "LAST" | "LAST.jtl") {
            PathKind::Last
        } else {
            PathKind::Explicit
        };
        Ok(Self { raw: value, kind })
    }

    fn new_jmeter_log(value: String) -> Result<Self, CliError> {
        if value.is_empty() {
            return Err(CliError::InvalidValue {
                option: OptionId::Jmeterlogfile,
                value,
                reason: ValueError::EmptyPath,
            });
        }
        let kind = if matches!(value.as_str(), "LAST" | "LAST.log") {
            PathKind::LastLiteral
        } else {
            PathKind::Explicit
        };
        Ok(Self { raw: value, kind })
    }

    /// Returns the exact user string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// Returns whether this value requests deferred `LAST` resolution.
    #[must_use]
    pub const fn is_last(&self) -> bool {
        matches!(self.kind, PathKind::Last | PathKind::LastLiteral)
    }

    /// Resolves a deferred `LAST` target against an explicitly supplied
    /// recent JMX path.  This pure helper mirrors JMeter's `processLAST`: a
    /// `LAST` or `LAST<suffix>` marker replaces a case-insensitive `.JMX`
    /// extension with `suffix`; a non-JMX recent path leaves the marker
    /// unresolved.  Ordinary explicit paths are returned unchanged.
    #[must_use]
    pub fn resolve_last_against(&self, recent_jmx: &Path, suffix: &str) -> Option<PathBuf> {
        if !matches!(self.kind, PathKind::Last) {
            return Some(PathBuf::from(&self.raw));
        }
        if self.raw != "LAST" && self.raw != format!("LAST{suffix}") {
            return Some(PathBuf::from(&self.raw));
        }
        let recent = recent_jmx.to_str()?;
        if !recent
            .get(recent.len().saturating_sub(4)..)?
            .eq_ignore_ascii_case(".jmx")
        {
            return None;
        }
        let stem_end = recent.len().saturating_sub(4);
        let mut resolved = String::with_capacity(stem_end + suffix.len());
        resolved.push_str(&recent[..stem_end]);
        resolved.push_str(suffix);
        Some(PathBuf::from(resolved))
    }
}

impl fmt::Debug for PathArgument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PathArgument")
            .field("raw", &self.raw)
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for PathArgument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.raw)
    }
}

/// Proxy options collected without applying process system properties.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct ProxyOptions {
    /// Optional proxy scheme (`http.proxyScheme`).
    pub scheme: Option<String>,
    /// Optional proxy host (`http.proxyHost`/`https.proxyHost`).
    pub host: Option<String>,
    /// Optional proxy port (`http.proxyPort`/`https.proxyPort`).
    pub port: Option<String>,
    /// Optional pipe-separated non-proxy host patterns.
    pub non_proxy_hosts: Option<String>,
    /// Optional proxy username.
    pub username: Option<String>,
    /// Optional proxy password.  Never rendered by [`fmt::Debug`] or
    /// [`fmt::Display`].
    pub password: Option<String>,
}

impl fmt::Debug for ProxyOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProxyOptions")
            .field("scheme", &self.scheme)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("non_proxy_hosts", &self.non_proxy_hosts)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl fmt::Display for ProxyOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "proxy(scheme={:?}, host={:?}, port={:?}, non_proxy_hosts={:?}, username={:?}, password=<redacted>)",
            self.scheme, self.host, self.port, self.non_proxy_hosts, self.username
        )
    }
}

/// A parsed logging level, retaining the exact user string.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogLevel {
    /// Exact value supplied to `-L`.
    pub raw: String,
    /// Optional logger category before the first equals sign.
    pub category: Option<String>,
    /// Logger level after the first equals sign, or the whole value.
    pub level: String,
}

impl LogLevel {
    fn parse(value: String) -> Result<Self, CliError> {
        if value.is_empty() {
            return Err(CliError::InvalidValue {
                option: OptionId::Loglevel,
                value,
                reason: ValueError::Empty,
            });
        }
        let (category, level) = match value.split_once('=') {
            Some((category, level)) if category.is_empty() || level.is_empty() => {
                return Err(CliError::InvalidValue {
                    option: OptionId::Loglevel,
                    value,
                    reason: ValueError::MissingLogLevel,
                });
            }
            Some((category, level)) => (Some(category.to_owned()), level.to_owned()),
            None => (None, value.clone()),
        };
        Ok(Self {
            raw: value,
            category,
            level,
        })
    }
}

/// Parsed proxy and remote controls.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RemoteOptions {
    /// Whether `-r` selected all configured remote hosts.
    pub run_remote: bool,
    /// Exact `-R` comma-separated host list, if supplied.
    pub remote_start: Option<String>,
    /// Whether `-X` requests remote shutdown after the run.
    pub remote_exit: bool,
}

/// Parsed options and derived mode.
#[derive(Clone, Eq, PartialEq)]
pub struct CliOptions {
    /// Selected execution mode.
    pub mode: RunMode,
    /// Whether the parser should take a non-execution action.
    pub action: Action,
    /// Primary JMeter property file (`-p`).
    pub propfile: Option<String>,
    /// Additional JMeter property files (`-q`), in user order.
    pub addprop: Vec<String>,
    /// Test plan path (`-t`), with deferred `LAST` interpretation.
    pub testfile: Option<PathArgument>,
    /// Result JTL path (`-l`), with deferred `LAST` interpretation.
    pub logfile: Option<PathArgument>,
    /// Log4j2 configuration path (`-i`).
    pub jmeterlogconf: Option<String>,
    /// JMeter run log path (`-j`), with deferred `LAST` interpretation.
    pub jmeterlogfile: Option<PathArgument>,
    /// Proxy settings collected from `-E/-H/-P/-N/-u/-a`.
    pub proxy: ProxyOptions,
    /// Local JMeter properties (`-J`), in user order.
    pub jmeter_properties: Vec<PropertyAssignment>,
    /// Remote/global properties (`-G`), in user order.
    pub global_properties: Vec<GlobalProperty>,
    /// System properties (`-D`), in user order.
    pub system_properties: Vec<PropertyAssignment>,
    /// Additional Java system-property files (`-S`), in user order.
    pub system_property_files: Vec<String>,
    /// Logging level overrides (`-L`), in user order.
    pub log_levels: Vec<LogLevel>,
    /// Force-delete result/report output before execution.
    pub force_delete_result_file: bool,
    /// Remote selection flags.
    pub remote: RemoteOptions,
    /// Report-only input JTL (`-g`).
    pub report_only_file: Option<String>,
    /// Generate a dashboard after a load test (`-e`).
    pub report_at_end: bool,
    /// Dashboard output directory (`-o`).
    pub report_output_folder: Option<String>,
    /// JMeter home directory (`-d`).
    pub home_dir: Option<String>,
    /// Exact occurrences in input order.
    pub occurrences: Vec<OptionOccurrence>,
    /// The explicit `--` terminator was present.
    pub option_terminator: bool,
}

impl fmt::Debug for CliOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("CliOptions");
        debug.field("mode", &self.mode);
        debug.field("action", &self.action);
        debug.field("propfile", &self.propfile);
        debug.field("addprop", &self.addprop);
        debug.field("testfile", &self.testfile);
        debug.field("logfile", &self.logfile);
        debug.field("jmeterlogconf", &self.jmeterlogconf);
        debug.field("jmeterlogfile", &self.jmeterlogfile);
        debug.field("proxy", &self.proxy);
        debug.field("jmeter_properties", &self.jmeter_properties);
        debug.field("global_properties", &self.global_properties);
        debug.field("system_properties", &self.system_properties);
        debug.field("system_property_files", &self.system_property_files);
        debug.field("log_levels", &self.log_levels);
        debug.field("force_delete_result_file", &self.force_delete_result_file);
        debug.field("remote", &self.remote);
        debug.field("report_only_file", &self.report_only_file);
        debug.field("report_at_end", &self.report_at_end);
        debug.field("report_output_folder", &self.report_output_folder);
        debug.field("home_dir", &self.home_dir);
        debug.field("occurrences", &self.occurrences);
        debug.field("option_terminator", &self.option_terminator);
        debug.finish()
    }
}

impl fmt::Display for CliOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "mode={}, action={:?}, testfile={:?}, logfile={:?}, proxy={}, occurrences={}",
            self.mode,
            self.action,
            self.testfile,
            self.logfile,
            self.proxy,
            self.occurrences.len()
        )
    }
}

impl CliOptions {
    /// Returns true when this is GUI/default mode.
    #[must_use]
    pub const fn is_gui(&self) -> bool {
        matches!(self.mode, RunMode::Gui)
    }

    /// Returns true when this is non-GUI/CLI mode.
    #[must_use]
    pub const fn is_nongui(&self) -> bool {
        matches!(self.mode, RunMode::NonGui)
    }

    /// Returns true when this is server mode.
    #[must_use]
    pub const fn is_server(&self) -> bool {
        matches!(self.mode, RunMode::Server)
    }

    /// Returns true when this is report-only mode.
    #[must_use]
    pub const fn is_report_only(&self) -> bool {
        matches!(self.mode, RunMode::ReportOnly)
    }

    /// Returns true when `-e` requests report generation after a load test.
    #[must_use]
    pub const fn report_at_end_of_load_tests(&self) -> bool {
        self.report_at_end
    }

    /// Builds the deterministic effect plan represented by these options.
    #[must_use]
    pub fn configuration_plan(&self) -> ConfigurationPlan {
        ConfigurationPlan::from_options(self)
    }
}

/// A parsed CLI invocation, including its deferred configuration plan.
#[derive(Clone, Eq, PartialEq)]
pub struct CliInvocation {
    /// Parsed option values.
    pub options: CliOptions,
    /// Action selected by help/version flags.
    pub action: Action,
    /// Deterministic ordered configuration/effect description.
    pub configuration: ConfigurationPlan,
}

impl fmt::Debug for CliInvocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CliInvocation")
            .field("options", &self.options)
            .field("action", &self.action)
            .field("configuration", &self.configuration)
            .finish()
    }
}

impl fmt::Display for CliInvocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.options.fmt(formatter)
    }
}

impl CliInvocation {
    /// Returns true when the invocation is a successful help/version action.
    #[must_use]
    pub const fn is_information_action(&self) -> bool {
        matches!(
            self.action,
            Action::Options | Action::Help | Action::Version
        )
    }

    /// Returns the selected mode.
    #[must_use]
    pub const fn mode(&self) -> RunMode {
        self.options.mode
    }

    /// Resolves the application-owned standalone HTTP provider selector.
    ///
    /// The selector is deliberately separate from JMeter's preserved HTTP
    /// implementation properties. [`HttpCapabilitySelector::Absent`] means
    /// that the source/JMeter provider remains authoritative; it never means
    /// that the native provider was selected implicitly.
    pub fn resolve_http_capability_selector(
        &self,
    ) -> Result<HttpCapabilitySelector, HttpCapabilitySelectorError> {
        resolve_http_capability_selector(self)
    }

    /// Resolves the optional, direct-command-line NativeV2 DNS/TLS policy.
    ///
    /// This is deliberately an occurrence-only operation. It does not read
    /// property files, inspect the environment, or touch the filesystem;
    /// plan admission later decides whether either optional value is needed.
    pub fn resolve_http_native_v2_properties(
        &self,
    ) -> Result<HttpNativeV2Properties, HttpNativeV2PropertyError> {
        resolve_http_native_v2_properties(self)
    }
}

/// Exact application-owned JMeter property key for standalone HTTP provider
/// selection.
pub const HTTP_CAPABILITY_SELECTOR_KEY: &str = "jmeter-rs.http.capability";

/// Exact versioned native HTTP capability selected by the standalone
/// provider property.
pub const HTTP_NATIVE_V1_CAPABILITY: &str = "http.native/1";

/// Exact versioned native HTTP capability selected by the standalone
/// provider property.
pub const HTTP_NATIVE_V2_CAPABILITY: &str = "http.native/2";

/// The application-owned standalone HTTP provider selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpCapabilitySelector {
    /// No direct selector was supplied. The source/JMeter provider remains
    /// authoritative and may require the optional compatibility pack.
    Absent,
    /// The exact direct `-Jjmeter-rs.http.capability=http.native/1` selector
    /// requested the independently named native provider.
    NativeV1,
    /// The exact direct `-Jjmeter-rs.http.capability=http.native/2` selector
    /// requested the separately versioned native provider increment.
    NativeV2,
}

impl HttpCapabilitySelector {
    /// Returns the stable selector identity, or `"absent"` when no
    /// application-owned override was supplied.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::NativeV1 => HTTP_NATIVE_V1_CAPABILITY,
            Self::NativeV2 => HTTP_NATIVE_V2_CAPABILITY,
        }
    }

    /// Returns whether either explicitly selected native HTTP provider was
    /// requested.
    #[must_use]
    pub const fn is_native(self) -> bool {
        matches!(self, Self::NativeV1 | Self::NativeV2)
    }

    /// Returns whether the native HTTP provider was explicitly selected.
    #[must_use]
    pub const fn is_native_v1(self) -> bool {
        matches!(self, Self::NativeV1)
    }

    /// Returns whether the separately versioned NativeV2 provider was
    /// explicitly selected.
    #[must_use]
    pub const fn is_native_v2(self) -> bool {
        matches!(self, Self::NativeV2)
    }
}

impl fmt::Display for HttpCapabilitySelector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Observable command-line source of an HTTP selector attempt.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum HttpCapabilitySelectorSource {
    /// The direct local JMeter property namespace supplied by `-J`.
    DirectJmeterProperty,
    /// A Java system-property assignment supplied by `-D`.
    SystemProperty,
    /// A remote/global-property assignment supplied by `-G`.
    GlobalProperty,
}

impl HttpCapabilitySelectorSource {
    /// Returns the stable source label used by diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DirectJmeterProperty => "direct -J JMeter property",
            Self::SystemProperty => "-D system property",
            Self::GlobalProperty => "-G global property",
        }
    }
}

impl fmt::Display for HttpCapabilitySelectorSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Stable typed failure while resolving the standalone HTTP selector.
#[derive(Clone, Eq, PartialEq)]
pub enum HttpCapabilitySelectorError {
    /// The direct selector was supplied with an empty value. In the
    /// configuration plan this is also the explicit property-removal form.
    Empty {
        /// Source carrying the empty value.
        source: HttpCapabilitySelectorSource,
    },
    /// More than one direct `-J` assignment attempted to select the provider.
    Repeated {
        /// Number of direct selector assignments observed.
        occurrences: usize,
    },
    /// The direct occurrence counter could not be incremented without
    /// overflowing its bounded integer representation.
    OccurrenceOverflow {
        /// Source whose direct occurrence count overflowed.
        source: HttpCapabilitySelectorSource,
    },
    /// A direct selector value is not a known versioned capability identity.
    UnknownValue {
        /// Source carrying the unknown value.
        source: HttpCapabilitySelectorSource,
        /// Exact value retained for typed callers; diagnostics redact it.
        value: String,
    },
    /// The selector was attempted through a source other than direct `-J`.
    NonDirectSource {
        /// Observable non-direct source carrying the value.
        source: HttpCapabilitySelectorSource,
        /// Exact value retained for typed callers; diagnostics redact it.
        value: String,
    },
}

impl HttpCapabilitySelectorError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Empty { .. } => "http.selector.empty",
            Self::Repeated { .. } => "http.selector.repeated",
            Self::OccurrenceOverflow { .. } => "http.selector.occurrence-overflow",
            Self::UnknownValue { .. } => "http.selector.unknown",
            Self::NonDirectSource { .. } => "http.selector.non-direct-source",
        }
    }

    /// Returns the CLI usage classification for selector failures.
    #[must_use]
    pub const fn exit_class(&self) -> ExitClass {
        ExitClass::UsageError
    }

    /// Returns the conventional process status for selector failures.
    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        self.exit_class().exit_code()
    }

    /// Returns the observable source involved in this failure. Repetition has
    /// only the direct `-J` source.
    #[must_use]
    pub const fn source(&self) -> HttpCapabilitySelectorSource {
        match self {
            Self::Empty { source }
            | Self::UnknownValue { source, .. }
            | Self::NonDirectSource { source, .. } => *source,
            Self::Repeated { .. } | Self::OccurrenceOverflow { .. } => {
                HttpCapabilitySelectorSource::DirectJmeterProperty
            }
        }
    }
}

impl fmt::Debug for HttpCapabilitySelectorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty { source } => formatter
                .debug_struct("Empty")
                .field("source", source)
                .finish(),
            Self::Repeated { occurrences } => formatter
                .debug_struct("Repeated")
                .field("occurrences", occurrences)
                .finish(),
            Self::OccurrenceOverflow { source } => formatter
                .debug_struct("OccurrenceOverflow")
                .field("source", source)
                .finish(),
            Self::UnknownValue { source, value } => formatter
                .debug_struct("UnknownValue")
                .field("source", source)
                .field("value", &redact_selector_value(value))
                .finish(),
            Self::NonDirectSource { source, value } => formatter
                .debug_struct("NonDirectSource")
                .field("source", source)
                .field("value", &redact_selector_value(value))
                .finish(),
        }
    }
}

impl fmt::Display for HttpCapabilitySelectorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty { source } => write!(
                formatter,
                "{}: {HTTP_CAPABILITY_SELECTOR_KEY} cannot be empty or removed ({source})",
                self.code()
            ),
            Self::Repeated { occurrences } => write!(
                formatter,
                "{}: {HTTP_CAPABILITY_SELECTOR_KEY} supplied {occurrences} times by direct -J",
                self.code()
            ),
            Self::OccurrenceOverflow { source } => write!(
                formatter,
                "{}: {HTTP_CAPABILITY_SELECTOR_KEY} occurrence count overflowed ({source})",
                self.code()
            ),
            Self::UnknownValue { source, value } => write!(
                formatter,
                "{}: unsupported {HTTP_CAPABILITY_SELECTOR_KEY} value {:?} ({source})",
                self.code(),
                redact_selector_value(value)
            ),
            Self::NonDirectSource { source, value } => write!(
                formatter,
                "{}: {HTTP_CAPABILITY_SELECTOR_KEY} must be supplied only by direct -J; found {:?} ({source})",
                self.code(),
                redact_selector_value(value)
            ),
        }
    }
}

impl std::error::Error for HttpCapabilitySelectorError {}

/// Exact direct JMeter property used to configure NativeV2 DNS.
pub const HTTP_DNS_NAMESERVERS_KEY: &str = "jmeter-rs.http.dns.nameservers";

/// Exact direct JMeter property used to configure NativeV2 trust roots.
pub const HTTP_TLS_CA_FILE_KEY: &str = "jmeter-rs.http.tls.ca-file";

/// Maximum number of explicit NativeV2 numeric nameservers.
pub const MAX_HTTP_NATIVE_V2_NAMESERVERS: usize = 16;

/// Maximum UTF-8 bytes retained for one NativeV2 direct property value.
///
/// The parser checks this bound on the borrowed occurrence value before it
/// allocates any typed nameserver or path representation.  The bound is
/// intentionally shared by the two properties so admission has one simple,
/// auditable resource limit.
pub const MAX_HTTP_NATIVE_V2_PROPERTY_BYTES: usize = 4096;

/// The exact command-line occurrence that supplied a NativeV2 property.
///
/// `occurrence` is the zero-based argv token index used by
/// `ConfigSource::CommandLine`, so a later filesystem-backed reconciliation
/// can match the typed value to the winning [`ResolvedConfig`] provenance
/// without retaining the raw property value here.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct HttpNativeV2PropertyOrigin {
    /// Observable CLI source. Successful values always use direct `-J`.
    pub source: HttpCapabilitySelectorSource,
    /// Zero-based option-token index in the original argv.
    pub occurrence: usize,
}

impl HttpNativeV2PropertyOrigin {
    /// Creates a direct `-J` origin for an option-token index.
    #[must_use]
    pub const fn direct(occurrence: usize) -> Self {
        Self {
            source: HttpCapabilitySelectorSource::DirectJmeterProperty,
            occurrence,
        }
    }
}

/// A validated, ordered NativeV2 nameserver list and its CLI provenance.
#[derive(Clone, Eq, PartialEq)]
pub struct HttpNativeV2Nameservers {
    /// Numeric UDP socket addresses in the exact user-supplied order.
    pub nameservers: Vec<SocketAddr>,
    /// The direct `-J` occurrence that supplied this list.
    pub origin: HttpNativeV2PropertyOrigin,
}

impl HttpNativeV2Nameservers {
    /// Returns the ordered numeric nameserver addresses.
    #[must_use]
    pub fn addresses(&self) -> &[SocketAddr] {
        &self.nameservers
    }

    /// Returns the argv occurrence that supplied this list.
    #[must_use]
    pub const fn origin(&self) -> HttpNativeV2PropertyOrigin {
        self.origin
    }
}

impl fmt::Debug for HttpNativeV2Nameservers {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpNativeV2Nameservers")
            .field("nameservers", &"<redacted>")
            .field("origin", &self.origin)
            .finish()
    }
}

/// A bounded relative CA-file token retained for later rooted resolution.
///
/// This type intentionally performs no filesystem access.  Its private
/// storage prevents callers from mutating a validated path into an absolute
/// or parent-containing path between admission and rooted resolution.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct HttpNativeV2CaFilePath(String);

impl HttpNativeV2CaFilePath {
    /// Returns the original bounded relative path token.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Borrows the path as a platform path without touching the filesystem.
    #[must_use]
    pub fn as_path(&self) -> &Path {
        Path::new(&self.0)
    }

    fn new(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl fmt::Debug for HttpNativeV2CaFilePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

impl fmt::Display for HttpNativeV2CaFilePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A validated NativeV2 CA-file token and its CLI provenance.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct HttpNativeV2CaFile {
    /// Bounded relative token to resolve beneath a later application root.
    pub path: HttpNativeV2CaFilePath,
    /// The direct `-J` occurrence that supplied this token.
    pub origin: HttpNativeV2PropertyOrigin,
}

impl HttpNativeV2CaFile {
    /// Returns the bounded relative path token.
    #[must_use]
    pub fn path(&self) -> &HttpNativeV2CaFilePath {
        &self.path
    }

    /// Returns the argv occurrence that supplied this token.
    #[must_use]
    pub const fn origin(&self) -> HttpNativeV2PropertyOrigin {
        self.origin
    }
}

impl fmt::Debug for HttpNativeV2CaFile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpNativeV2CaFile")
            .field("path", &self.path)
            .field("origin", &self.origin)
            .finish()
    }
}

/// Optional direct NativeV2 CLI policy.
///
/// Both fields are optional because whether a nameserver or CA file is
/// required depends on the later plan's hostname/HTTPS admission.  An
/// explicitly empty, removed, repeated, malformed, or non-direct occurrence
/// is still rejected by the resolver.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HttpNativeV2Properties {
    /// Optional explicit numeric nameserver list.
    pub dns_nameservers: Option<HttpNativeV2Nameservers>,
    /// Optional explicit relative CA-file token.
    pub tls_ca_file: Option<HttpNativeV2CaFile>,
}

impl HttpNativeV2Properties {
    /// Returns the optional ordered nameserver list.
    #[must_use]
    pub fn nameservers(&self) -> Option<&[SocketAddr]> {
        self.dns_nameservers
            .as_ref()
            .map(HttpNativeV2Nameservers::addresses)
    }

    /// Returns the optional CA-file selection.
    #[must_use]
    pub fn ca_file(&self) -> Option<&HttpNativeV2CaFilePath> {
        self.tls_ca_file.as_ref().map(HttpNativeV2CaFile::path)
    }

    /// Returns whether neither optional property was supplied.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.dns_nameservers.is_none() && self.tls_ca_file.is_none()
    }
}

/// Reasons a numeric nameserver entry is not accepted by NativeV2.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpNativeV2NameserverError {
    /// The complete value was empty.
    Empty,
    /// A comma-separated entry was empty.
    EmptyEntry,
    /// Whitespace makes the entry's tokenization ambiguous.
    Whitespace,
    /// The entry was not a numeric IP or socket address.
    NonNumeric,
    /// An IPv6 socket address supplied a port without brackets.
    UnbracketedIpv6Port,
    /// A bracketed socket address was malformed or used a non-IPv6 host.
    InvalidSocket,
    /// The explicit socket port was not the required DNS port 53.
    PortNot53 {
        /// Parsed explicit port.
        port: u16,
    },
    /// The endpoint used an unspecified/zero IP address or port.
    Zero,
    /// The same numeric socket address appeared more than once.
    Duplicate,
    /// More than the bounded number of entries was supplied.
    TooMany {
        /// Number of comma-separated entries observed.
        count: usize,
    },
}

impl fmt::Display for HttpNativeV2NameserverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("nameserver value is empty (<redacted>)"),
            Self::EmptyEntry => formatter.write_str("nameserver entry is empty (<redacted>)"),
            Self::Whitespace => {
                formatter.write_str("nameserver value contains whitespace (<redacted>)")
            }
            Self::NonNumeric => formatter.write_str("nameserver entry is not numeric (<redacted>)"),
            Self::UnbracketedIpv6Port => {
                formatter.write_str("IPv6 nameserver ports require brackets (<redacted>)")
            }
            Self::InvalidSocket => formatter.write_str("nameserver socket is invalid (<redacted>)"),
            Self::PortNot53 { port } => {
                write!(formatter, "nameserver port {port} is not 53 (<redacted>)")
            }
            Self::Zero => formatter.write_str("nameserver address or port is zero (<redacted>)"),
            Self::Duplicate => formatter.write_str("duplicate nameserver (<redacted>)"),
            Self::TooMany { count } => write!(
                formatter,
                "{count} nameservers exceed the maximum of {MAX_HTTP_NATIVE_V2_NAMESERVERS}"
            ),
        }
    }
}

/// Reasons a NativeV2 CA-file token is rejected before rooted resolution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpNativeV2CaPathError {
    /// The path token is empty.
    Empty,
    /// The path contains a NUL byte.
    Nul,
    /// The path is absolute for the current or a recognized foreign platform.
    Absolute,
    /// The path contains a parent component.
    Parent,
    /// The path contains a root component.
    Root,
    /// The path contains a platform prefix or drive/UNC form.
    Prefix,
}

impl fmt::Display for HttpNativeV2CaPathError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reason = match self {
            Self::Empty => "path is empty",
            Self::Nul => "path contains NUL",
            Self::Absolute => "path is absolute",
            Self::Parent => "path contains a parent component",
            Self::Root => "path contains a root component",
            Self::Prefix => "path contains a platform prefix",
        };
        write!(formatter, "{reason} (<redacted>)")
    }
}

/// Stable typed failure while resolving NativeV2 direct properties.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HttpNativeV2PropertyError {
    /// A direct assignment supplied an empty value or explicit removal.
    Empty {
        /// Exact property key.
        property: &'static str,
        /// Observable source carrying the empty assignment.
        source: HttpCapabilitySelectorSource,
        /// Original argv option-token index.
        occurrence: usize,
    },
    /// More than one direct `-J` assignment supplied the same key.
    Repeated {
        /// Exact property key.
        property: &'static str,
        /// Number of direct assignments observed.
        occurrences: usize,
    },
    /// The direct occurrence counter could not be incremented without
    /// overflowing its bounded integer representation.
    OccurrenceOverflow {
        /// Exact property key whose direct occurrence count overflowed.
        property: &'static str,
    },
    /// A same-key `-D`/`-G` occurrence was observed.
    NonDirectSource {
        /// Exact property key.
        property: &'static str,
        /// Observable non-direct source.
        source: HttpCapabilitySelectorSource,
        /// Original argv option-token index.
        occurrence: usize,
    },
    /// A raw value exceeded the copy/parse bound.
    ValueTooLong {
        /// Exact property key.
        property: &'static str,
        /// Maximum accepted UTF-8 bytes.
        limit: usize,
        /// Observed UTF-8 bytes, retained only as a count.
        observed: usize,
        /// Original argv option-token index.
        occurrence: usize,
    },
    /// A nameserver list failed bounded numeric validation.
    InvalidNameservers {
        /// Original argv option-token index.
        occurrence: usize,
        /// Zero-based comma-separated entry index, where applicable.
        entry: Option<usize>,
        /// Typed validation reason.
        reason: HttpNativeV2NameserverError,
    },
    /// A CA-file token failed bounded relative-path validation.
    InvalidCaFile {
        /// Original argv option-token index.
        occurrence: usize,
        /// Typed validation reason.
        reason: HttpNativeV2CaPathError,
    },
}

impl HttpNativeV2PropertyError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Empty { .. } => "http.native-v2.property.empty",
            Self::Repeated { .. } => "http.native-v2.property.repeated",
            Self::OccurrenceOverflow { .. } => "http.native-v2.property.occurrence-overflow",
            Self::NonDirectSource { .. } => "http.native-v2.property.non-direct-source",
            Self::ValueTooLong { .. } => "http.native-v2.property.value-limit",
            Self::InvalidNameservers { reason, .. } => match reason {
                HttpNativeV2NameserverError::TooMany { .. } => {
                    "http.native-v2.dns.nameservers.too-many"
                }
                _ => "http.native-v2.dns.nameservers.invalid",
            },
            Self::InvalidCaFile { reason, .. } => match reason {
                HttpNativeV2CaPathError::Empty => "http.native-v2.tls.ca-file.empty",
                HttpNativeV2CaPathError::Absolute => "http.native-v2.tls.ca-file.absolute",
                HttpNativeV2CaPathError::Parent => "http.native-v2.tls.ca-file.parent",
                HttpNativeV2CaPathError::Root => "http.native-v2.tls.ca-file.root",
                HttpNativeV2CaPathError::Prefix => "http.native-v2.tls.ca-file.prefix",
                HttpNativeV2CaPathError::Nul => "http.native-v2.tls.ca-file.nul",
            },
        }
    }

    /// Returns the CLI usage classification for this pure parser failure.
    #[must_use]
    pub const fn exit_class(&self) -> ExitClass {
        ExitClass::UsageError
    }

    /// Returns the conventional process status for this failure.
    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        self.exit_class().exit_code()
    }

    /// Returns the exact key involved when one is available.
    #[must_use]
    pub const fn property(&self) -> &'static str {
        match self {
            Self::Empty { property, .. }
            | Self::Repeated { property, .. }
            | Self::OccurrenceOverflow { property }
            | Self::NonDirectSource { property, .. }
            | Self::ValueTooLong { property, .. } => property,
            Self::InvalidNameservers { .. } => HTTP_DNS_NAMESERVERS_KEY,
            Self::InvalidCaFile { .. } => HTTP_TLS_CA_FILE_KEY,
        }
    }

    /// Returns the original argv option-token index, when one exists.
    #[must_use]
    pub const fn occurrence(&self) -> Option<usize> {
        match self {
            Self::Empty { occurrence, .. }
            | Self::InvalidNameservers { occurrence, .. }
            | Self::InvalidCaFile { occurrence, .. }
            | Self::NonDirectSource { occurrence, .. }
            | Self::ValueTooLong { occurrence, .. } => Some(*occurrence),
            Self::Repeated { .. } | Self::OccurrenceOverflow { .. } => None,
        }
    }
}

impl fmt::Display for HttpNativeV2PropertyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty {
                property,
                source,
                occurrence,
            } => write!(
                formatter,
                "{}: {property} cannot be empty or removed ({source}, occurrence {occurrence})",
                self.code()
            ),
            Self::Repeated {
                property,
                occurrences,
            } => write!(
                formatter,
                "{}: {property} supplied {occurrences} times by direct -J",
                self.code()
            ),
            Self::OccurrenceOverflow { property } => write!(
                formatter,
                "{}: {property} direct occurrence count overflowed",
                self.code()
            ),
            Self::NonDirectSource {
                property,
                source,
                occurrence,
            } => write!(
                formatter,
                "{}: {property} must be supplied only by direct -J; found <redacted> ({source}, occurrence {occurrence})",
                self.code()
            ),
            Self::ValueTooLong {
                property,
                limit,
                observed,
                occurrence,
            } => write!(
                formatter,
                "{}: {property} value is {observed} bytes; maximum is {limit} (occurrence {occurrence}, <redacted>)",
                self.code()
            ),
            Self::InvalidNameservers {
                occurrence,
                entry,
                reason,
            } => write!(
                formatter,
                "{}: {HTTP_DNS_NAMESERVERS_KEY} entry {} is invalid: {reason} (occurrence {occurrence})",
                self.code(),
                entry.map_or_else(|| "<list>".to_owned(), |value| value.to_string())
            ),
            Self::InvalidCaFile { occurrence, reason } => write!(
                formatter,
                "{}: {HTTP_TLS_CA_FILE_KEY} is invalid: {reason} (occurrence {occurrence})",
                self.code()
            ),
        }
    }
}

impl std::error::Error for HttpNativeV2PropertyError {}

fn redact_selector_value(value: &str) -> String {
    if looks_like_sensitive_value(value) {
        REDACTED_CLI_VALUE.to_owned()
    } else {
        redact_cli_token(value)
    }
}

/// Resolves the one application-owned HTTP selector visible in a parsed CLI
/// invocation. File-backed/default/environment sources are intentionally not
/// read here; their contents are outside this pure parser boundary and cannot
/// authorize a native provider.
pub fn resolve_http_capability_selector(
    invocation: &CliInvocation,
) -> Result<HttpCapabilitySelector, HttpCapabilitySelectorError> {
    let mut direct_occurrences = 0usize;
    let mut direct_value = None;
    let mut non_direct = None;

    for occurrence in &invocation.options.occurrences {
        let Some(raw) = occurrence.value() else {
            continue;
        };
        let Some(value) = direct_property_value(raw, HTTP_CAPABILITY_SELECTOR_KEY) else {
            continue;
        };
        match occurrence.id {
            OptionId::Jmeterproperty => {
                direct_occurrences = direct_occurrences.checked_add(1).ok_or(
                    HttpCapabilitySelectorError::OccurrenceOverflow {
                        source: HttpCapabilitySelectorSource::DirectJmeterProperty,
                    },
                )?;
                if direct_occurrences == 1 {
                    direct_value = Some(value);
                }
            }
            OptionId::Systemproperty | OptionId::Globalproperty if non_direct.is_none() => {
                let source = if occurrence.id == OptionId::Systemproperty {
                    HttpCapabilitySelectorSource::SystemProperty
                } else {
                    HttpCapabilitySelectorSource::GlobalProperty
                };
                non_direct = Some((source, value));
            }
            _ => {}
        }
    }

    if direct_occurrences > 1 {
        return Err(HttpCapabilitySelectorError::Repeated {
            occurrences: direct_occurrences,
        });
    }
    if let Some((source, value)) = non_direct {
        return Err(HttpCapabilitySelectorError::NonDirectSource {
            source,
            value: value.to_owned(),
        });
    }
    let Some(value) = direct_value else {
        return Ok(HttpCapabilitySelector::Absent);
    };
    if value.is_empty() {
        return Err(HttpCapabilitySelectorError::Empty {
            source: HttpCapabilitySelectorSource::DirectJmeterProperty,
        });
    }
    if value == HTTP_NATIVE_V1_CAPABILITY {
        return Ok(HttpCapabilitySelector::NativeV1);
    }
    if value == HTTP_NATIVE_V2_CAPABILITY {
        return Ok(HttpCapabilitySelector::NativeV2);
    }
    Err(HttpCapabilitySelectorError::UnknownValue {
        source: HttpCapabilitySelectorSource::DirectJmeterProperty,
        value: value.to_owned(),
    })
}

/// Resolves the optional NativeV2 DNS/TLS properties from raw CLI
/// occurrences.  Only direct `-J` assignments are accepted; property files,
/// environment values, and `-D`/`-G` assignments are intentionally outside
/// this pure boundary.
pub fn resolve_http_native_v2_properties(
    invocation: &CliInvocation,
) -> Result<HttpNativeV2Properties, HttpNativeV2PropertyError> {
    let dns_nameservers = resolve_native_v2_nameservers(invocation)?;
    let tls_ca_file = resolve_native_v2_ca_file(invocation)?;
    Ok(HttpNativeV2Properties {
        dns_nameservers,
        tls_ca_file,
    })
}

fn resolve_native_v2_nameservers(
    invocation: &CliInvocation,
) -> Result<Option<HttpNativeV2Nameservers>, HttpNativeV2PropertyError> {
    let Some((value, origin)) = find_native_v2_assignment(invocation, HTTP_DNS_NAMESERVERS_KEY)?
    else {
        return Ok(None);
    };
    if value.len() > MAX_HTTP_NATIVE_V2_PROPERTY_BYTES {
        return Err(HttpNativeV2PropertyError::ValueTooLong {
            property: HTTP_DNS_NAMESERVERS_KEY,
            limit: MAX_HTTP_NATIVE_V2_PROPERTY_BYTES,
            observed: value.len(),
            occurrence: origin.occurrence,
        });
    }
    let nameservers = parse_native_v2_nameservers(value).map_err(|(entry, reason)| {
        HttpNativeV2PropertyError::InvalidNameservers {
            occurrence: origin.occurrence,
            entry,
            reason,
        }
    })?;
    Ok(Some(HttpNativeV2Nameservers {
        nameservers,
        origin,
    }))
}

fn resolve_native_v2_ca_file(
    invocation: &CliInvocation,
) -> Result<Option<HttpNativeV2CaFile>, HttpNativeV2PropertyError> {
    let Some((value, origin)) = find_native_v2_assignment(invocation, HTTP_TLS_CA_FILE_KEY)? else {
        return Ok(None);
    };
    if value.len() > MAX_HTTP_NATIVE_V2_PROPERTY_BYTES {
        return Err(HttpNativeV2PropertyError::ValueTooLong {
            property: HTTP_TLS_CA_FILE_KEY,
            limit: MAX_HTTP_NATIVE_V2_PROPERTY_BYTES,
            observed: value.len(),
            occurrence: origin.occurrence,
        });
    }
    let path = parse_native_v2_ca_file(value).map_err(|reason| {
        HttpNativeV2PropertyError::InvalidCaFile {
            occurrence: origin.occurrence,
            reason,
        }
    })?;
    Ok(Some(HttpNativeV2CaFile { path, origin }))
}

/// Finds exactly one direct assignment for a NativeV2 property while
/// retaining the original argv token index.  The returned value borrows the
/// already-parsed occurrence and is copied only after its bound is checked by
/// the property-specific resolver.
fn find_native_v2_assignment<'a>(
    invocation: &'a CliInvocation,
    property: &'static str,
) -> Result<Option<(&'a str, HttpNativeV2PropertyOrigin)>, HttpNativeV2PropertyError> {
    let mut direct_occurrences = 0usize;
    let mut direct = None;
    let mut non_direct = None;

    for occurrence in &invocation.options.occurrences {
        let Some(raw) = occurrence.value() else {
            continue;
        };
        let Some(value) = direct_property_value(raw, property) else {
            continue;
        };
        match occurrence.id {
            OptionId::Jmeterproperty => {
                direct_occurrences = direct_occurrences
                    .checked_add(1)
                    .ok_or(HttpNativeV2PropertyError::OccurrenceOverflow { property })?;
                if direct_occurrences == 1 {
                    direct = Some((value, HttpNativeV2PropertyOrigin::direct(occurrence.index)));
                }
            }
            OptionId::Systemproperty | OptionId::Globalproperty if non_direct.is_none() => {
                let source = if occurrence.id == OptionId::Systemproperty {
                    HttpCapabilitySelectorSource::SystemProperty
                } else {
                    HttpCapabilitySelectorSource::GlobalProperty
                };
                non_direct = Some((source, occurrence.index));
            }
            _ => {}
        }
    }

    if direct_occurrences > 1 {
        return Err(HttpNativeV2PropertyError::Repeated {
            property,
            occurrences: direct_occurrences,
        });
    }
    if let Some((source, occurrence)) = non_direct {
        return Err(HttpNativeV2PropertyError::NonDirectSource {
            property,
            source,
            occurrence,
        });
    }
    let Some((value, origin)) = direct else {
        return Ok(None);
    };
    if value.is_empty() {
        return Err(HttpNativeV2PropertyError::Empty {
            property,
            source: origin.source,
            occurrence: origin.occurrence,
        });
    }
    Ok(Some((value, origin)))
}

/// Returns the value for an exact property assignment in a parsed command
/// line occurrence.  A key without `=` is the CLI's explicit removal form
/// and therefore maps to the empty value; unrelated keys remain absent.
fn direct_property_value<'a>(raw: &'a str, property: &str) -> Option<&'a str> {
    match raw.split_once('=') {
        Some((key, value)) if key == property => Some(value),
        None if raw == property => Some(""),
        _ => None,
    }
}

/// Parses one bounded comma-separated numeric nameserver list.
fn parse_native_v2_nameservers(
    value: &str,
) -> Result<Vec<SocketAddr>, (Option<usize>, HttpNativeV2NameserverError)> {
    if value.is_empty() {
        return Err((None, HttpNativeV2NameserverError::Empty));
    }
    if value.chars().any(char::is_whitespace) {
        return Err((None, HttpNativeV2NameserverError::Whitespace));
    }
    // Stop counting once the bounded limit has been exceeded.  The returned
    // `count` is therefore at most `MAX + 1`, even if a future caller raises
    // the value-byte bound substantially.
    let count = value
        .splitn(MAX_HTTP_NATIVE_V2_NAMESERVERS + 1, ',')
        .count();
    if count > MAX_HTTP_NATIVE_V2_NAMESERVERS {
        return Err((None, HttpNativeV2NameserverError::TooMany { count }));
    }

    let mut addresses = Vec::with_capacity(count);
    for (entry_index, entry) in value.split(',').enumerate() {
        if entry.is_empty() {
            return Err((Some(entry_index), HttpNativeV2NameserverError::EmptyEntry));
        }
        let address = parse_native_v2_nameserver_entry(entry)
            .map_err(|reason| (Some(entry_index), reason))?;
        if address.port() == 0 || address.ip().is_unspecified() {
            return Err((Some(entry_index), HttpNativeV2NameserverError::Zero));
        }
        if address.port() != 53 {
            return Err((
                Some(entry_index),
                HttpNativeV2NameserverError::PortNot53 {
                    port: address.port(),
                },
            ));
        }
        if addresses.contains(&address) {
            return Err((Some(entry_index), HttpNativeV2NameserverError::Duplicate));
        }
        addresses.push(address);
    }
    Ok(addresses)
}

fn parse_native_v2_nameserver_entry(
    entry: &str,
) -> Result<SocketAddr, HttpNativeV2NameserverError> {
    if entry.starts_with('[') {
        let Some(close) = entry.find(']') else {
            return Err(HttpNativeV2NameserverError::InvalidSocket);
        };
        let inner = &entry[1..close];
        let Ok(ip) = inner.parse::<IpAddr>() else {
            return Err(HttpNativeV2NameserverError::InvalidSocket);
        };
        if !ip.is_ipv6()
            || entry.as_bytes().get(close + 1) != Some(&b':')
            || close + 2 > entry.len()
        {
            return Err(HttpNativeV2NameserverError::InvalidSocket);
        }
        let Ok(address) = entry.parse::<SocketAddr>() else {
            return Err(HttpNativeV2NameserverError::InvalidSocket);
        };
        return Ok(address);
    }

    if let Ok(ip) = entry.parse::<IpAddr>() {
        if ip.is_ipv6() && looks_like_unbracketed_ipv6_socket(entry) {
            return Err(HttpNativeV2NameserverError::UnbracketedIpv6Port);
        }
        return Ok(SocketAddr::new(ip, 53));
    }

    entry
        .parse::<SocketAddr>()
        .map_err(|_| HttpNativeV2NameserverError::NonNumeric)
}

/// Detects the ambiguous `2001:db8::1:53` form.  A bare IPv6 address is
/// accepted when it has no separately parseable IPv6 prefix before a numeric
/// final field (for example `::1`); an explicit port must use brackets.
fn looks_like_unbracketed_ipv6_socket(value: &str) -> bool {
    let Some((prefix, port)) = value.rsplit_once(':') else {
        return false;
    };
    !prefix.is_empty() && port.parse::<u16>().is_ok() && prefix.parse::<IpAddr>().is_ok()
}

fn parse_native_v2_ca_file(value: &str) -> Result<HttpNativeV2CaFilePath, HttpNativeV2CaPathError> {
    if value.is_empty() {
        return Err(HttpNativeV2CaPathError::Empty);
    }
    if value.contains('\0') {
        return Err(HttpNativeV2CaPathError::Nul);
    }
    let path = Path::new(value);
    if path.is_absolute() {
        return Err(HttpNativeV2CaPathError::Absolute);
    }
    if looks_like_native_v2_path_prefix(value) {
        return Err(HttpNativeV2CaPathError::Prefix);
    }
    if value.starts_with('\\') {
        return Err(HttpNativeV2CaPathError::Root);
    }
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
        || value.split(['/', '\\']).any(|component| component == "..")
    {
        return Err(HttpNativeV2CaPathError::Parent);
    }
    if path
        .components()
        .any(|component| matches!(component, Component::RootDir | Component::Prefix(_)))
    {
        return Err(HttpNativeV2CaPathError::Root);
    }
    Ok(HttpNativeV2CaFilePath::new(value))
}

fn looks_like_native_v2_path_prefix(value: &str) -> bool {
    if value.starts_with("//") || value.starts_with("\\\\") {
        return true;
    }
    value.as_bytes().get(1).is_some_and(|byte| *byte == b':')
}

/// Compatibility alias for callers that call the parsed value `Cli`.
pub type Cli = CliInvocation;

/// Compatibility alias for callers that call the parsed value `ParsedCli`.
pub type ParsedCli = CliInvocation;

/// The source role of a property load in [`ConfigurationPlan`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PropertySource {
    /// The explicitly selected primary file from `-p`.
    ExplicitPrimary {
        /// Exact user path.
        path: String,
    },
    /// The default `jmeter.properties` source.
    DefaultPrimary,
    /// The default `user.properties` source.
    DefaultUser,
    /// The default `system.properties` source.
    DefaultSystem,
    /// A `-q` additional JMeter property file.
    AdditionalJmeter {
        /// Exact user path.
        path: String,
        /// Original occurrence index.
        occurrence: usize,
    },
    /// An `-S` additional system-property file.
    AdditionalSystem {
        /// Exact user path.
        path: String,
        /// Original occurrence index.
        occurrence: usize,
    },
    /// A `-G` global-property file.
    Global {
        /// Exact user path.
        path: String,
        /// Original occurrence index.
        occurrence: usize,
    },
}

/// A deferred log target.  The application runner resolves `LAST` only when
/// the launch environment supplies an explicit recent-project path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LogTarget {
    /// The default JMeter log target.
    Default,
    /// An explicit or deferred user target.
    Selected(PathArgument),
}

/// Ordered effect description consumed by the application edge.
#[derive(Clone, Eq, PartialEq)]
pub enum ConfigurationStep {
    /// Load the primary property source.
    LoadProperties {
        /// Source role and exact path where applicable.
        source: PropertySource,
    },
    /// Select the JMeter run log before logger initialization.
    SelectJmeterLog {
        /// Default or user-selected target.
        target: LogTarget,
    },
    /// Initialize logging from the optional Log4j2 file and selected target.
    InitializeLogging {
        /// `-i` path, if supplied.
        config_file: Option<String>,
        /// The selected run-log target.
        target: LogTarget,
    },
    /// Load the default user property source.
    LoadUserProperties {
        /// Source role.
        source: PropertySource,
    },
    /// Load the default system property source.
    LoadSystemProperties {
        /// Source role.
        source: PropertySource,
    },
    /// Apply a local JMeter property assignment.
    ApplyJmeterProperty {
        /// Exact assignment.
        assignment: PropertyAssignment,
        /// Original occurrence index.
        occurrence: usize,
    },
    /// Apply or load a global property.
    ApplyGlobalProperty {
        /// Assignment or file source.
        property: GlobalProperty,
        /// Original occurrence index.
        occurrence: usize,
    },
    /// Apply a system property assignment.
    ApplySystemProperty {
        /// Exact assignment.
        assignment: PropertyAssignment,
        /// Original occurrence index.
        occurrence: usize,
    },
    /// Apply a proxy setting to the local system-property adapter.
    ApplyProxy {
        /// Exact property key.
        key: &'static str,
        /// Exact value; password values are redacted by the plan formatter.
        value: String,
        /// Whether the value is sensitive.
        sensitive: bool,
        /// Original occurrence index.
        occurrence: usize,
    },
    /// Apply a logging level override.
    ApplyLogLevel {
        /// Parsed logging level.
        level: LogLevel,
        /// Original occurrence index.
        occurrence: usize,
    },
    /// Select the plan/result/report paths for the explicit local
    /// engine/report adapters.  This step performs no filesystem access.
    SelectInputs {
        /// Test plan path, if any.
        testfile: Option<PathArgument>,
        /// Result path, if any.
        logfile: Option<PathArgument>,
        /// Report-only input, if any.
        report_only_file: Option<String>,
        /// Dashboard output path, if any.
        report_output_folder: Option<String>,
    },
}

impl fmt::Debug for ConfigurationStep {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApplyProxy {
                key,
                value,
                sensitive,
                occurrence,
            } => {
                let value = if *sensitive {
                    "<redacted>"
                } else {
                    value.as_str()
                };
                formatter
                    .debug_struct("ApplyProxy")
                    .field("key", key)
                    .field("value", &value)
                    .field("sensitive", sensitive)
                    .field("occurrence", occurrence)
                    .finish()
            }
            Self::LoadProperties { source } => formatter
                .debug_struct("LoadProperties")
                .field("source", source)
                .finish(),
            Self::SelectJmeterLog { target } => formatter
                .debug_struct("SelectJmeterLog")
                .field("target", target)
                .finish(),
            Self::InitializeLogging {
                config_file,
                target,
            } => formatter
                .debug_struct("InitializeLogging")
                .field("config_file", config_file)
                .field("target", target)
                .finish(),
            Self::LoadUserProperties { source } => formatter
                .debug_struct("LoadUserProperties")
                .field("source", source)
                .finish(),
            Self::LoadSystemProperties { source } => formatter
                .debug_struct("LoadSystemProperties")
                .field("source", source)
                .finish(),
            Self::ApplyJmeterProperty {
                assignment,
                occurrence,
            } => formatter
                .debug_struct("ApplyJmeterProperty")
                .field("assignment", assignment)
                .field("occurrence", occurrence)
                .finish(),
            Self::ApplyGlobalProperty {
                property,
                occurrence,
            } => formatter
                .debug_struct("ApplyGlobalProperty")
                .field("property", property)
                .field("occurrence", occurrence)
                .finish(),
            Self::ApplySystemProperty {
                assignment,
                occurrence,
            } => formatter
                .debug_struct("ApplySystemProperty")
                .field("assignment", assignment)
                .field("occurrence", occurrence)
                .finish(),
            Self::ApplyLogLevel { level, occurrence } => formatter
                .debug_struct("ApplyLogLevel")
                .field("level", level)
                .field("occurrence", occurrence)
                .finish(),
            Self::SelectInputs {
                testfile,
                logfile,
                report_only_file,
                report_output_folder,
            } => formatter
                .debug_struct("SelectInputs")
                .field("testfile", testfile)
                .field("logfile", logfile)
                .field("report_only_file", report_only_file)
                .field("report_output_folder", report_output_folder)
                .finish(),
        }
    }
}

/// A deterministic sequence of configuration steps.  It is deliberately
/// descriptive rather than executable: no file, environment, logger, or
/// process operation occurs while creating one.
#[derive(Clone, Eq, PartialEq)]
pub struct ConfigurationPlan {
    /// Ordered steps in the exact order an application adapter must consider.
    pub steps: Vec<ConfigurationStep>,
}

impl fmt::Debug for ConfigurationPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfigurationPlan")
            .field("steps", &self.steps)
            .finish()
    }
}

impl ConfigurationPlan {
    fn from_options(options: &CliOptions) -> Self {
        let mut steps = Vec::new();
        let primary = match &options.propfile {
            Some(path) => PropertySource::ExplicitPrimary { path: path.clone() },
            None => PropertySource::DefaultPrimary,
        };
        steps.push(ConfigurationStep::LoadProperties { source: primary });

        let log_target = options
            .jmeterlogfile
            .clone()
            .map_or(LogTarget::Default, LogTarget::Selected);
        steps.push(ConfigurationStep::SelectJmeterLog {
            target: log_target.clone(),
        });
        steps.push(ConfigurationStep::InitializeLogging {
            config_file: options.jmeterlogconf.clone(),
            target: log_target,
        });
        steps.push(ConfigurationStep::LoadUserProperties {
            source: PropertySource::DefaultUser,
        });
        steps.push(ConfigurationStep::LoadSystemProperties {
            source: PropertySource::DefaultSystem,
        });

        for occurrence in &options.occurrences {
            match occurrence.id {
                OptionId::Addprop => {
                    if let Some(path) = occurrence.value.clone() {
                        steps.push(ConfigurationStep::LoadProperties {
                            source: PropertySource::AdditionalJmeter {
                                path,
                                occurrence: occurrence.index,
                            },
                        });
                    }
                }
                OptionId::SystemPropertyFile => {
                    if let Some(path) = occurrence.value.clone() {
                        steps.push(ConfigurationStep::LoadProperties {
                            source: PropertySource::AdditionalSystem {
                                path,
                                occurrence: occurrence.index,
                            },
                        });
                    }
                }
                OptionId::Jmeterproperty => {
                    if let Some(value) = occurrence.value.clone()
                        && let Ok(assignment) = PropertyAssignment::parse(occurrence.id, value)
                    {
                        steps.push(ConfigurationStep::ApplyJmeterProperty {
                            assignment,
                            occurrence: occurrence.index,
                        });
                    }
                }
                OptionId::Globalproperty => {
                    if let Some(value) = occurrence.value.clone()
                        && let Ok(property) = GlobalProperty::parse(value)
                    {
                        steps.push(ConfigurationStep::ApplyGlobalProperty {
                            property,
                            occurrence: occurrence.index,
                        });
                    }
                }
                OptionId::Systemproperty => {
                    if let Some(value) = occurrence.value.clone()
                        && let Ok(assignment) = PropertyAssignment::parse(occurrence.id, value)
                    {
                        steps.push(ConfigurationStep::ApplySystemProperty {
                            assignment,
                            occurrence: occurrence.index,
                        });
                    }
                }
                OptionId::Loglevel => {
                    if let Some(value) = occurrence.value.clone()
                        && let Ok(level) = LogLevel::parse(value)
                    {
                        steps.push(ConfigurationStep::ApplyLogLevel {
                            level,
                            occurrence: occurrence.index,
                        });
                    }
                }
                // Proxy flags are applied after the property loop by
                // `setProxy`; append them below in that fixed startup phase
                // rather than treating their argv position as precedence.
                OptionId::ProxyScheme
                | OptionId::ProxyHost
                | OptionId::ProxyPort
                | OptionId::NonProxyHosts
                | OptionId::Username
                | OptionId::Password => {}
                _ => {}
            }
        }

        let proxy_occurrence = |id| {
            options
                .occurrences
                .iter()
                .find(|occurrence| occurrence.id == id)
                .map(|occurrence| occurrence.index)
        };
        if let (Some(value), Some(occurrence)) = (
            options.proxy.username.clone(),
            proxy_occurrence(OptionId::Username),
        ) {
            steps.push(ConfigurationStep::ApplyProxy {
                key: "http.proxyUser",
                value,
                sensitive: false,
                occurrence,
            });
        }
        if options.proxy.username.is_some()
            && let (Some(value), Some(occurrence)) = (
                options.proxy.password.clone(),
                proxy_occurrence(OptionId::Password),
            )
        {
            steps.push(ConfigurationStep::ApplyProxy {
                key: "http.proxyPass",
                value,
                sensitive: true,
                occurrence,
            });
        }
        if let (Some(value), Some(occurrence)) = (
            options.proxy.host.clone(),
            proxy_occurrence(OptionId::ProxyHost),
        ) {
            steps.push(ConfigurationStep::ApplyProxy {
                key: "http.proxyHost/https.proxyHost",
                value,
                sensitive: false,
                occurrence,
            });
        }
        if let (Some(value), Some(occurrence)) = (
            options.proxy.port.clone(),
            proxy_occurrence(OptionId::ProxyPort),
        ) {
            steps.push(ConfigurationStep::ApplyProxy {
                key: "http.proxyPort/https.proxyPort",
                value,
                sensitive: false,
                occurrence,
            });
        }
        if options.proxy.host.is_some()
            && options.proxy.port.is_some()
            && let (Some(value), Some(occurrence)) = (
                options
                    .proxy
                    .scheme
                    .clone()
                    .filter(|value| !value.trim().is_empty()),
                proxy_occurrence(OptionId::ProxyScheme),
            )
        {
            steps.push(ConfigurationStep::ApplyProxy {
                key: "http.proxyScheme",
                value,
                sensitive: false,
                occurrence,
            });
        }
        if let (Some(value), Some(occurrence)) = (
            options.proxy.non_proxy_hosts.clone(),
            proxy_occurrence(OptionId::NonProxyHosts),
        ) {
            steps.push(ConfigurationStep::ApplyProxy {
                key: "http.nonProxyHosts/https.nonProxyHosts",
                value,
                sensitive: false,
                occurrence,
            });
        }

        steps.push(ConfigurationStep::SelectInputs {
            testfile: options.testfile.clone(),
            logfile: options.logfile.clone(),
            report_only_file: options.report_only_file.clone(),
            report_output_folder: options.report_output_folder.clone(),
        });
        Self { steps }
    }

    /// Returns the ordered steps.
    #[must_use]
    pub fn steps(&self) -> &[ConfigurationStep] {
        &self.steps
    }

    /// Returns only property loading/apply steps, retaining their order.
    #[must_use = "iterate the ordered property/configuration steps"]
    pub fn property_steps(&self) -> impl Iterator<Item = &ConfigurationStep> {
        self.steps.iter().filter(|step| {
            matches!(
                step,
                ConfigurationStep::LoadProperties { .. }
                    | ConfigurationStep::LoadUserProperties { .. }
                    | ConfigurationStep::LoadSystemProperties { .. }
                    | ConfigurationStep::ApplyJmeterProperty { .. }
                    | ConfigurationStep::ApplyGlobalProperty { .. }
                    | ConfigurationStep::ApplySystemProperty { .. }
                    | ConfigurationStep::ApplyProxy { .. }
                    | ConfigurationStep::ApplyLogLevel { .. }
            )
        })
    }
}

/// Parses arguments excluding the executable name.
pub fn parse<I, S>(arguments: I) -> Result<CliInvocation, CliError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    parse_strings(
        arguments
            .into_iter()
            .map(|argument| argument.as_ref().to_owned())
            .collect(),
    )
}

/// Parses an argument slice excluding the executable name.
pub fn parse_strings(arguments: Vec<String>) -> Result<CliInvocation, CliError> {
    let occurrences = parse_occurrences(&arguments)?;
    let mut options = build_options(occurrences)?;
    options.option_terminator = arguments.iter().any(|argument| argument == "--");
    let action = options.action;
    let configuration = options.configuration_plan();
    Ok(CliInvocation {
        options,
        action,
        configuration,
    })
}

/// Parses OS arguments excluding the executable name.  Values must be valid
/// UTF-8 because JMeter property names, paths, and diagnostics are strings at
/// this boundary; non-UTF-8 input fails explicitly instead of being lossy.
pub fn parse_os<I, S>(arguments: I) -> Result<CliInvocation, CliError>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let mut strings = Vec::new();
    for argument in arguments {
        let argument: OsString = argument.into();
        let Some(argument) = argument.to_str() else {
            return Err(CliError::NonUnicodeArgument);
        };
        strings.push(argument.to_owned());
    }
    parse_strings(strings)
}

/// Generates help text from [`OPTION_TABLE`].
#[must_use]
pub fn help_text() -> String {
    let mut output = ascii_art_text();
    output.push('\n');
    output.push_str(include_str!("resources/help.txt"));
    output.push('\n');
    output
}

/// Renders the pinned option catalog used by the `-?` action.
#[must_use]
pub fn options_text() -> String {
    let mut output = ascii_art_text();
    output.push('\n');
    for spec in OPTION_TABLE {
        output.push('\t');
        if let Some(short) = spec.short.filter(|value| value.len() == 1) {
            output.push('-');
            output.push_str(short);
            output.push_str(", ");
        }
        output.push_str("--");
        output.push_str(spec.long);
        if spec.takes_value {
            output.push_str(" <argument>");
            if matches!(
                spec.id,
                OptionId::Jmeterproperty
                    | OptionId::Globalproperty
                    | OptionId::Systemproperty
                    | OptionId::Loglevel
            ) {
                output.push_str("=<value>");
            }
        }
        output.push('\n');
        let mut description = spec.description;
        while description.len() > 60 {
            output.push_str("\t\t");
            output.push_str(&description[..60]);
            output.push('\n');
            description = &description[60..];
        }
        output.push_str("\t\t");
        output.push_str(description);
        output.push('\n');
    }
    output.push('\n');
    output
}

/// Generates version text for the binary.
#[must_use]
pub fn version_text() -> String {
    let mut output = ascii_art_text();
    output.push('\n');
    output
}

fn ascii_art_text() -> String {
    include_str!("resources/jmeter_as_ascii_art.txt")
        .replace("@VERSION@", JMETER_COMPATIBILITY_VERSION)
        .replace("@YEAR@", "2024")
}

fn lookup_long(name: &str) -> Option<OptionId> {
    OPTION_TABLE
        .iter()
        .find(|spec| spec.long == name)
        .map(|spec| spec.id)
}

fn lookup_short(name: &str) -> Option<OptionId> {
    if name == "?" {
        return Some(OptionId::Help);
    }
    OPTION_TABLE
        .iter()
        .find(|spec| spec.short == Some(name))
        .map(|spec| spec.id)
}

fn occurrence_value_is_sensitive(id: OptionId, value: Option<&str>) -> bool {
    if id == OptionId::Password {
        return true;
    }
    if !matches!(
        id,
        OptionId::Jmeterproperty | OptionId::Globalproperty | OptionId::Systemproperty
    ) {
        return false;
    }
    let Some((key, _)) = value.and_then(|value| value.split_once('=')) else {
        return false;
    };
    is_sensitive_key(key)
}

/// Shared conservative property-key redaction policy used by both the
/// parser and filesystem-backed resolver.  Matching is case-insensitive and
/// recognizes token/secret/credential families in addition to password
/// aliases, including dotted, dashed, and underscored names.
fn is_sensitive_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key.ends_with("password")
        || key.ends_with("passwd")
        || key.ends_with("secret")
        || key.ends_with("token")
        || key.ends_with("credential")
        || key.ends_with("credentials")
        || key.ends_with("proxypass")
        || key.ends_with("proxy.password")
        || key.split(['.', '_', '-']).any(|segment| {
            matches!(
                segment,
                "password" | "passwd" | "secret" | "token" | "credential" | "credentials"
            )
        })
}

const REDACTED_CLI_VALUE: &str = "<redacted>";

fn looks_like_sensitive_name(name: &str) -> bool {
    let normalized = name.trim_start_matches('-');
    let lower = normalized.to_ascii_lowercase();
    is_sensitive_key(&lower)
        || lower.contains("pass")
        || lower.contains("secret")
        || lower.contains("token")
        || lower.contains("credential")
}

fn looks_like_sensitive_literal(value: &str) -> bool {
    matches!(
        value
            .trim()
            .trim_matches(['"', '\''])
            .to_ascii_lowercase()
            .as_str(),
        "password" | "passwd" | "secret" | "token" | "credential" | "credentials"
    )
}

fn looks_like_sensitive_value(value: &str) -> bool {
    let normalized = value.trim().trim_matches(['"', '\'']).to_ascii_lowercase();
    looks_like_sensitive_literal(&normalized)
        || normalized.contains("password")
        || normalized.contains("passwd")
        || normalized.contains("secret")
        || normalized.contains("token")
        || normalized.contains("credential")
}

fn cli_assignment(token: &str) -> Option<(&str, &str, char)> {
    let index = token.find(['=', ':'])?;
    let (prefix, suffix) = token.split_at(index);
    let delimiter = suffix.chars().next()?;
    Some((prefix, &suffix[delimiter.len_utf8()..], delimiter))
}

fn redact_cli_token(token: &str) -> String {
    if let Some((prefix, value, delimiter)) = cli_assignment(token)
        && (looks_like_sensitive_name(prefix)
            || looks_like_sensitive_value(value)
            || value.to_ascii_lowercase().contains("password=")
            || value.to_ascii_lowercase().contains("secret=")
            || value.to_ascii_lowercase().contains("token="))
    {
        return format!("{prefix}{delimiter}{REDACTED_CLI_VALUE}");
    }
    if looks_like_sensitive_literal(token) {
        REDACTED_CLI_VALUE.to_owned()
    } else {
        token.to_owned()
    }
}

fn redact_option_spelling(option: OptionId, spelling: &str) -> String {
    if option == OptionId::Password && !matches!(spelling, "-a" | "--password") {
        if spelling.starts_with("--password") {
            return format!("--password={REDACTED_CLI_VALUE}");
        }
        if spelling.starts_with("-a") {
            return format!("-a={REDACTED_CLI_VALUE}");
        }
    }
    redact_cli_token(spelling)
}

fn redact_cli_value(option: OptionId, value: &str) -> String {
    if option == OptionId::Password {
        return REDACTED_CLI_VALUE.to_owned();
    }
    if let Some((key, _, _)) = cli_assignment(value)
        && looks_like_sensitive_name(key)
    {
        return REDACTED_CLI_VALUE.to_owned();
    }
    redact_cli_token(value)
}

fn parse_occurrences(arguments: &[String]) -> Result<Vec<OptionOccurrence>, CliError> {
    let mut occurrences = Vec::new();
    let mut index = 0;
    let mut terminated = false;
    while index < arguments.len() {
        let token = &arguments[index];
        if terminated {
            return Err(CliError::UnexpectedArgument {
                argument: token.clone(),
            });
        }
        if token == "--" {
            terminated = true;
            index += 1;
            continue;
        }
        if token == "-" || !token.starts_with('-') {
            return Err(CliError::UnexpectedArgument {
                argument: token.clone(),
            });
        }
        if let Some(long_token) = token.strip_prefix("--") {
            let (name, attached) = long_token
                .split_once('=')
                .map_or((long_token, None), |(name, value)| (name, Some(value)));
            let Some(id) = lookup_long(name) else {
                return Err(CliError::UnknownOption {
                    token: token.clone(),
                });
            };
            let spec = option_spec(id);
            let (value, consumed_next, arguments_used) = consume_value(
                &spec,
                id,
                token,
                attached.map(str::to_owned),
                arguments.get(index + 1),
            )?;
            let sensitive = occurrence_value_is_sensitive(id, value.as_deref());
            occurrences.push(OptionOccurrence {
                id,
                spelling: token.clone(),
                value,
                arguments: arguments_used,
                index,
                sensitive,
            });
            index += 1 + consumed_next;
            continue;
        }

        let short_token = token.strip_prefix('-').unwrap_or(token);
        let first = short_token.get(0..1).unwrap_or_default();
        let Some(first_id) = lookup_short(first) else {
            return Err(CliError::UnknownOption {
                token: token.clone(),
            });
        };
        let first_spec = option_spec(first_id);
        if first_spec.takes_value {
            let remainder = short_token.get(first.len()..).unwrap_or_default();
            let attached = (!remainder.is_empty())
                .then(|| remainder.strip_prefix('=').unwrap_or(remainder).to_owned());
            let (value, consumed_next, arguments_used) = consume_value(
                &first_spec,
                first_id,
                token,
                attached,
                arguments.get(index + 1),
            )?;
            let sensitive = occurrence_value_is_sensitive(first_id, value.as_deref());
            occurrences.push(OptionOccurrence {
                id: first_id,
                spelling: token.clone(),
                value,
                arguments: arguments_used,
                index,
                sensitive,
            });
            index += 1 + consumed_next;
            continue;
        }

        // Commons CLI accepts compact clusters of flag options.  We accept
        // them only for flags, never by swallowing the value of an option.
        for (offset, character) in short_token.char_indices() {
            let next_offset = offset + character.len_utf8();
            let spelling = format!("-{}", character);
            let name = character.to_string();
            let Some(id) = lookup_short(&name) else {
                return Err(CliError::UnknownOption { token: spelling });
            };
            let spec = option_spec(id);
            if spec.takes_value {
                return Err(CliError::UnknownOption {
                    token: token.clone(),
                });
            }
            if next_offset < short_token.len() && id == OptionId::Help {
                // `-?x` is not a valid flag cluster; retaining the exact
                // token in the error makes this deterministic and safe.
                return Err(CliError::UnknownOption {
                    token: token.clone(),
                });
            }
            occurrences.push(OptionOccurrence {
                id,
                spelling,
                value: None,
                arguments: Vec::new(),
                index,
                sensitive: false,
            });
        }
        index += 1;
    }
    Ok(occurrences)
}

fn consume_value(
    spec: &OptionSpec,
    id: OptionId,
    spelling: &str,
    attached: Option<String>,
    next: Option<&String>,
) -> Result<(Option<String>, usize, Vec<String>), CliError> {
    if !spec.takes_value {
        if attached.is_some() {
            return Err(CliError::UnexpectedValue {
                option: id,
                spelling: spelling.to_owned(),
            });
        }
        return Ok((None, 0, Vec::new()));
    }
    let two_arguments = matches!(
        id,
        OptionId::Jmeterproperty
            | OptionId::Globalproperty
            | OptionId::Systemproperty
            | OptionId::Loglevel
    );
    if let Some(value) = attached {
        if value.is_empty() {
            return Err(CliError::InvalidValue {
                option: id,
                value,
                reason: ValueError::Empty,
            });
        }
        if two_arguments {
            let arguments = value.split_once('=').map_or_else(
                || vec![value.clone(), String::new()],
                |(first, second)| vec![first.to_owned(), second.to_owned()],
            );
            if arguments.first().is_none_or(String::is_empty) {
                return Err(CliError::InvalidValue {
                    option: id,
                    value,
                    reason: ValueError::MissingAssignment,
                });
            }
            return Ok((Some(normalize_two_argument(id, &arguments)), 0, arguments));
        }
        return Ok((Some(value.clone()), 0, vec![value]));
    }
    let Some(next) = next else {
        return Err(CliError::MissingValue {
            option: id,
            spelling: spelling.to_owned(),
        });
    };
    if next == "--" {
        return Err(CliError::MissingValue {
            option: id,
            spelling: spelling.to_owned(),
        });
    }
    if next.is_empty() {
        return Err(CliError::InvalidValue {
            option: id,
            value: next.clone(),
            reason: ValueError::Empty,
        });
    }
    if !two_arguments {
        return Ok((Some(next.clone()), 1, vec![next.clone()]));
    }
    let first = next.clone();
    let arguments = if two_arguments {
        first.split_once('=').map_or_else(
            || vec![first.clone(), String::new()],
            |(key, value)| vec![key.to_owned(), value.to_owned()],
        )
    } else {
        vec![first]
    };
    if two_arguments && arguments.first().is_none_or(String::is_empty) {
        return Err(CliError::InvalidValue {
            option: id,
            value: next.clone(),
            reason: ValueError::MissingAssignment,
        });
    }
    Ok((
        Some(if two_arguments {
            normalize_two_argument(id, &arguments)
        } else {
            arguments[0].clone()
        }),
        1,
        arguments,
    ))
}

fn normalize_two_argument(id: OptionId, arguments: &[String]) -> String {
    let first = arguments.first().map(String::as_str).unwrap_or_default();
    let second = arguments.get(1).map(String::as_str).unwrap_or_default();
    if first.contains('=') || (id == OptionId::Loglevel && second.is_empty()) {
        first.to_owned()
    } else {
        format!("{first}={second}")
    }
}

fn build_options(occurrences: Vec<OptionOccurrence>) -> Result<CliOptions, CliError> {
    if OPTION_TABLE.len() != 30 {
        return Err(CliError::InvalidOptionTable);
    }
    let mut action = Action::Execute;
    let mut action_id = None;
    let mut mode_flag = None;
    let mut options = CliOptions {
        mode: RunMode::Gui,
        action,
        propfile: None,
        addprop: Vec::new(),
        testfile: None,
        logfile: None,
        jmeterlogconf: None,
        jmeterlogfile: None,
        proxy: ProxyOptions::default(),
        jmeter_properties: Vec::new(),
        global_properties: Vec::new(),
        system_properties: Vec::new(),
        system_property_files: Vec::new(),
        log_levels: Vec::new(),
        force_delete_result_file: false,
        remote: RemoteOptions::default(),
        report_only_file: None,
        report_at_end: false,
        report_output_folder: None,
        home_dir: None,
        occurrences,
        option_terminator: false,
    };

    let mut seen_singletons = Vec::new();
    for occurrence in &options.occurrences {
        let id = occurrence.id;
        if !id.repeatable() {
            if seen_singletons.contains(&id) {
                return Err(CliError::DuplicateOption {
                    option: id,
                    spelling: occurrence.spelling.clone(),
                });
            }
            seen_singletons.push(id);
        }
        match id {
            OptionId::Help => {
                set_action(&mut action, &mut action_id, Action::Options, id)?;
            }
            OptionId::HelpLong => {
                set_action(&mut action, &mut action_id, Action::Help, id)?;
            }
            OptionId::Version => {
                set_action(&mut action, &mut action_id, Action::Version, id)?;
            }
            OptionId::Propfile => options.propfile = Some(required_value(occurrence)?),
            OptionId::Addprop => options.addprop.push(required_value(occurrence)?),
            OptionId::Testfile => {
                options.testfile = Some(PathArgument::new(required_value(occurrence)?)?);
            }
            OptionId::Logfile => {
                options.logfile = Some(PathArgument::new_log(required_value(occurrence)?)?);
            }
            OptionId::Jmeterlogconf => options.jmeterlogconf = Some(required_value(occurrence)?),
            OptionId::Jmeterlogfile => {
                options.jmeterlogfile =
                    Some(PathArgument::new_jmeter_log(required_value(occurrence)?)?);
            }
            OptionId::Nongui => set_mode(&mut mode_flag, OptionId::Nongui)?,
            OptionId::Server => set_mode(&mut mode_flag, OptionId::Server)?,
            OptionId::ProxyScheme => options.proxy.scheme = Some(required_value(occurrence)?),
            OptionId::ProxyHost => options.proxy.host = Some(required_value(occurrence)?),
            OptionId::ProxyPort => options.proxy.port = Some(required_value(occurrence)?),
            OptionId::NonProxyHosts => {
                options.proxy.non_proxy_hosts = Some(required_value(occurrence)?);
            }
            OptionId::Username => options.proxy.username = Some(required_value(occurrence)?),
            OptionId::Password => options.proxy.password = Some(required_value(occurrence)?),
            OptionId::Jmeterproperty => options
                .jmeter_properties
                .push(PropertyAssignment::parse(id, required_value(occurrence)?)?),
            OptionId::Globalproperty => options
                .global_properties
                .push(GlobalProperty::parse(required_value(occurrence)?)?),
            OptionId::Systemproperty => options
                .system_properties
                .push(PropertyAssignment::parse(id, required_value(occurrence)?)?),
            OptionId::SystemPropertyFile => options
                .system_property_files
                .push(required_value(occurrence)?),
            OptionId::ForceDeleteResultFile => options.force_delete_result_file = true,
            OptionId::Loglevel => options
                .log_levels
                .push(LogLevel::parse(required_value(occurrence)?)?),
            OptionId::Runremote => options.remote.run_remote = true,
            OptionId::Remotestart => {
                options.remote.remote_start = Some(required_value(occurrence)?);
            }
            OptionId::Homedir => options.home_dir = Some(required_value(occurrence)?),
            OptionId::Remoteexit => options.remote.remote_exit = true,
            OptionId::Reportonly => {
                options.report_only_file = Some(required_value(occurrence)?);
                set_mode(&mut mode_flag, OptionId::Reportonly)?;
            }
            OptionId::Reportatendofloadtests => options.report_at_end = true,
            OptionId::Reportoutputfolder => {
                options.report_output_folder = Some(required_value(occurrence)?);
            }
        }
    }

    options.action = action;
    options.mode = match mode_flag {
        Some(OptionId::Nongui) => RunMode::NonGui,
        Some(OptionId::Server) => RunMode::Server,
        Some(OptionId::Reportonly) => RunMode::ReportOnly,
        None => RunMode::Gui,
        Some(_) => return Err(CliError::InvalidOptionTable),
    };
    validate_combinations(&options)?;
    Ok(options)
}

fn required_value(occurrence: &OptionOccurrence) -> Result<String, CliError> {
    occurrence
        .value
        .clone()
        .ok_or_else(|| CliError::MissingValue {
            option: occurrence.id,
            spelling: occurrence.spelling.clone(),
        })
}

fn set_action(
    action: &mut Action,
    action_id: &mut Option<OptionId>,
    requested: Action,
    id: OptionId,
) -> Result<(), CliError> {
    // JMeter checks these selectors in fixed priority order after parsing:
    // version, then long help, then the options/help alias.  Do not let argv
    // order make `-? -v` behave differently from `-v -?`.
    let priority = |value: Action| match value {
        Action::Execute => 0_u8,
        Action::Options => 1,
        Action::Help => 2,
        Action::Version => 3,
    };
    if action_id.is_none() || priority(requested) > priority(*action) {
        *action = requested;
        *action_id = Some(id);
    }
    Ok(())
}

fn set_mode(mode: &mut Option<OptionId>, id: OptionId) -> Result<(), CliError> {
    if let Some(previous) = *mode
        && previous != id
    {
        return Err(CliError::IncompatibleOptions {
            options: vec![previous, id],
            reason: CombinationError::MultipleModes,
        });
    }
    *mode = Some(id);
    Ok(())
}

fn validate_combinations(options: &CliOptions) -> Result<(), CliError> {
    // Proxy host/port validation occurs during JMeter startup before its
    // informational action branches, so malformed proxy pairs do not become
    // silently accepted merely because `--version`/`--help` was selected.
    if options.proxy.host.is_some() != options.proxy.port.is_some() {
        return Err(CliError::IncompatibleOptions {
            options: vec![OptionId::ProxyHost, OptionId::ProxyPort],
            reason: CombinationError::ProxyNeedsHostAndPort,
        });
    }

    let remote_selected = options.remote.run_remote
        || options.remote.remote_start.is_some()
        || options.remote.remote_exit;
    // JMeter performs this mode guard immediately after Commons CLI parsing,
    // before the later version/help/options display branches.  Retaining it
    // here means `-? -r` and `-h -X` do not silently hide an invalid mode.
    if remote_selected && !options.is_nongui() && !options.is_report_only() {
        let mut conflicts = vec![OptionId::Nongui];
        if options.remote.run_remote {
            conflicts.push(OptionId::Runremote);
        }
        if options.remote.remote_start.is_some() {
            conflicts.push(OptionId::Remotestart);
        }
        if options.remote.remote_exit {
            conflicts.push(OptionId::Remoteexit);
        }
        return Err(CliError::IncompatibleOptions {
            options: conflicts,
            reason: CombinationError::RemoteNeedsNonGui,
        });
    }
    if options.is_report_only()
        && (options.logfile.is_some()
            || options.remote.run_remote
            || options.remote.remote_start.is_some())
    {
        let mut conflicts = vec![OptionId::Reportonly];
        if options.logfile.is_some() {
            conflicts.push(OptionId::Logfile);
        }
        if options.remote.run_remote {
            conflicts.push(OptionId::Runremote);
        }
        if options.remote.remote_start.is_some() {
            conflicts.push(OptionId::Remotestart);
        }
        return Err(CliError::IncompatibleOptions {
            options: conflicts,
            reason: CombinationError::ReportOnlyConflict,
        });
    }
    if options.is_report_only() && options.testfile.is_some() {
        return Err(CliError::IncompatibleOptions {
            options: vec![OptionId::Reportonly, OptionId::Testfile],
            reason: CombinationError::ReportOnlyNeedsOnlyJtl,
        });
    }
    if matches!(
        options.action,
        Action::Options | Action::Help | Action::Version
    ) {
        return Ok(());
    }

    if options.is_nongui() && options.testfile.is_none() {
        return Err(CliError::IncompatibleOptions {
            options: vec![OptionId::Nongui],
            reason: CombinationError::NonGuiNeedsTestfile,
        });
    }

    if options.report_at_end && !options.is_report_only() {
        if options.logfile.is_none() {
            return Err(CliError::IncompatibleOptions {
                options: vec![OptionId::Reportatendofloadtests],
                reason: CombinationError::ReportAtEndNeedsLogfile,
            });
        }
        if !options.is_nongui() {
            return Err(CliError::IncompatibleOptions {
                options: vec![OptionId::Reportatendofloadtests],
                reason: CombinationError::ReportAtEndNeedsNonGui,
            });
        }
    }

    if !options.is_report_only() && options.report_only_file.is_some() {
        return Err(CliError::IncompatibleOptions {
            options: vec![OptionId::Reportonly],
            reason: CombinationError::ReportOnlyNeedsOnlyJtl,
        });
    }

    if options.report_output_folder.is_some() && !options.is_report_only() && !options.report_at_end
    {
        return Err(CliError::IncompatibleOptions {
            options: vec![OptionId::Reportoutputfolder],
            reason: CombinationError::ReportOutputNeedsReport,
        });
    }

    if remote_selected && !options.is_nongui() && !options.is_report_only() {
        let mut conflicts = vec![OptionId::Nongui];
        if options.remote.run_remote {
            conflicts.push(OptionId::Runremote);
        }
        if options.remote.remote_start.is_some() {
            conflicts.push(OptionId::Remotestart);
        }
        if options.remote.remote_exit {
            conflicts.push(OptionId::Remoteexit);
        }
        return Err(CliError::IncompatibleOptions {
            options: conflicts,
            reason: CombinationError::RemoteNeedsNonGui,
        });
    }
    if options.is_server()
        && (options.testfile.is_some()
            || options.logfile.is_some()
            || options.remote.run_remote
            || options.remote.remote_start.is_some()
            || options.remote.remote_exit
            || options.report_at_end
            || options.report_output_folder.is_some())
    {
        return Err(CliError::IncompatibleOptions {
            options: vec![OptionId::Server],
            reason: CombinationError::ServerConflict,
        });
    }
    Ok(())
}

/// Renders a redacted diagnostic for an arbitrary displayable value.
///
/// This helper is primarily useful to process adapters that want to include
/// parsed options in a structured diagnostic without accidentally formatting
/// proxy credentials.  It returns the same output as `Display` for the
/// redacting types in this module.
#[must_use]
pub fn redacted_debug(options: &CliOptions) -> String {
    format!("{options:?}")
}

/// Convert a platform argument to UTF-8 for callers that want the same
/// explicit policy as [`parse_os`].
pub fn os_to_string(value: &OsStr) -> Result<String, CliError> {
    value
        .to_str()
        .map(str::to_owned)
        .ok_or(CliError::NonUnicodeArgument)
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "parser tests use explicit assertion setup"
)]
mod tests {
    use super::*;

    fn parse_ok(arguments: &[&str]) -> CliInvocation {
        parse(arguments.iter().map(|value| (*value).to_owned())).expect("arguments parse")
    }

    #[test]
    fn embedded_assets_match_pinned_digests_and_manifest_identity() {
        assert!(!STANDALONE_CAPABILITY_SET_BYTES.is_empty());
        assert!(!JMETER_COMPATIBILITY_PROFILE_BYTES.is_empty());
        assert_eq!(
            STANDALONE_NATIVE_PATHS.len(),
            STANDALONE_NATIVE_CAPABILITIES.len()
        );
        for ((_, capability, version), (expected_capability, expected_version)) in
            STANDALONE_NATIVE_PATHS
                .iter()
                .zip(STANDALONE_NATIVE_CAPABILITIES.iter())
        {
            assert_eq!(capability, expected_capability);
            assert_eq!(version, expected_version);
        }
        assert_eq!(
            standalone_capability_set_digest().as_bytes(),
            STANDALONE_CAPABILITY_SET_SHA256
        );
        assert_eq!(
            compatibility_profile_digest().as_bytes(),
            JMETER_COMPATIBILITY_PROFILE_SHA256
        );

        let identity = standalone_manifest_identity().expect("embedded manifest validates");
        assert_eq!(
            identity.capability_set_digest(),
            standalone_capability_set_digest()
        );
        assert_eq!(identity.capability_set_id, STANDALONE_CAPABILITY_SET_ID);
        assert_eq!(
            identity.capability_set_version,
            STANDALONE_CAPABILITY_SET_VERSION
        );
        assert_eq!(identity.profile.id, JMETER_COMPATIBILITY_PROFILE);
        assert_eq!(
            identity.profile.version,
            JMETER_COMPATIBILITY_PROFILE_VERSION
        );
        assert_eq!(
            identity.profile.digest.as_bytes(),
            JMETER_COMPATIBILITY_PROFILE_SHA256
        );
        assert_eq!(
            identity.capability_set_digest.as_bytes(),
            STANDALONE_CAPABILITY_SET_SHA256
        );
    }

    #[test]
    fn standalone_runtime_set_is_native_only_and_validates_plan_digest() {
        let plan_digest = Digest32::from_bytes([0x42; 32]);
        let set = standalone_runtime_capability_set(plan_digest).expect("native set");
        assert_eq!(
            set.mode(),
            jmeter_rs_runtime::AdmissionMode::StandaloneNative
        );
        assert_eq!(set.plan_digest(), plan_digest);
        assert_eq!(
            set.capability_set_digest().as_bytes(),
            STANDALONE_CAPABILITY_SET_SHA256
        );
        match set {
            RuntimeCapabilitySet::StandaloneNative { capabilities, .. } => {
                assert_eq!(capabilities.len(), STANDALONE_NATIVE_CAPABILITIES.len());
                assert!(capabilities.iter().all(|capability| {
                    STANDALONE_NATIVE_CAPABILITIES
                        .iter()
                        .any(|&(id, version)| capability.id == id && capability.version == version)
                }));
            }
            RuntimeCapabilitySet::CompatibilityPack { .. } => {
                panic!("standalone projection selected a compatibility pack")
            }
        }

        let error = standalone_runtime_capability_set(Digest32::from_bytes([0; 32]))
            .expect_err("zero plan digest is rejected");
        assert_eq!(error.exit_class(), ExitClass::UnsupportedCapability);
        assert_eq!(error.exit_code(), 78);
        assert!(matches!(
            error,
            StandaloneManifestError::CapabilitySetIdentity(
                jmeter_rs_runtime::CapabilityIdentityError {
                    code: jmeter_rs_runtime::CapabilityIdentityErrorCode::ZeroDigest,
                    field: "plan.digest",
                    ..
                }
            )
        ));
    }

    #[test]
    fn sha256_asset_helper_matches_published_vector() {
        assert_eq!(
            sha256_bytes(b"abc"),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
    }

    #[test]
    fn option_table_contains_every_documented_option_once() {
        assert_eq!(OPTION_TABLE.len(), 30);
        let expected = [
            (OptionId::Help, Some("?"), "?"),
            (OptionId::HelpLong, Some("h"), "help"),
            (OptionId::Version, Some("v"), "version"),
            (OptionId::Propfile, Some("p"), "propfile"),
            (OptionId::Addprop, Some("q"), "addprop"),
            (OptionId::Testfile, Some("t"), "testfile"),
            (OptionId::Logfile, Some("l"), "logfile"),
            (OptionId::Jmeterlogconf, Some("i"), "jmeterlogconf"),
            (OptionId::Jmeterlogfile, Some("j"), "jmeterlogfile"),
            (OptionId::Nongui, Some("n"), "nongui"),
            (OptionId::Server, Some("s"), "server"),
            (OptionId::ProxyScheme, Some("E"), "proxyScheme"),
            (OptionId::ProxyHost, Some("H"), "proxyHost"),
            (OptionId::ProxyPort, Some("P"), "proxyPort"),
            (OptionId::NonProxyHosts, Some("N"), "nonProxyHosts"),
            (OptionId::Username, Some("u"), "username"),
            (OptionId::Password, Some("a"), "password"),
            (OptionId::Jmeterproperty, Some("J"), "jmeterproperty"),
            (OptionId::Globalproperty, Some("G"), "globalproperty"),
            (OptionId::Systemproperty, Some("D"), "systemproperty"),
            (
                OptionId::SystemPropertyFile,
                Some("S"),
                "systemPropertyFile",
            ),
            (
                OptionId::ForceDeleteResultFile,
                Some("f"),
                "forceDeleteResultFile",
            ),
            (OptionId::Loglevel, Some("L"), "loglevel"),
            (OptionId::Runremote, Some("r"), "runremote"),
            (OptionId::Remotestart, Some("R"), "remotestart"),
            (OptionId::Homedir, Some("d"), "homedir"),
            (OptionId::Remoteexit, Some("X"), "remoteexit"),
            (OptionId::Reportonly, Some("g"), "reportonly"),
            (
                OptionId::Reportatendofloadtests,
                Some("e"),
                "reportatendofloadtests",
            ),
            (
                OptionId::Reportoutputfolder,
                Some("o"),
                "reportoutputfolder",
            ),
        ];
        let actual = OPTION_TABLE
            .iter()
            .map(|spec| (spec.id, spec.short, spec.long))
            .collect::<Vec<_>>();
        assert_eq!(actual.as_slice(), expected.as_slice());
        let mut ids = OPTION_TABLE.iter().map(|spec| spec.id).collect::<Vec<_>>();
        ids.sort_by_key(|id| *id as u8);
        ids.dedup();
        assert_eq!(ids.len(), OPTION_TABLE.len());
        assert!(OPTION_TABLE.iter().any(|spec| spec.short == Some("E")));
        assert!(
            OPTION_TABLE
                .iter()
                .any(|spec| spec.long == "systemPropertyFile")
        );
        assert!(OPTION_TABLE.iter().any(|spec| spec.short == Some("?")));
    }

    #[test]
    fn exit_classification_table_has_stable_codes_and_statuses() {
        let expected = [
            (ExitClass::Success, "ok", 0),
            (ExitClass::SampleFailure, "sample.failure", 0),
            (ExitClass::UsageError, "cli.usage", 2),
            (ExitClass::ConfigurationError, "config.invalid", 78),
            (
                ExitClass::UnsupportedCapability,
                "capability.unavailable",
                78,
            ),
            (ExitClass::Fatal, "fatal", 1),
            (ExitClass::RemoteFailure, "remote.failure", 1),
            (ExitClass::InternalError, "internal.error", 70),
        ];
        for (class, code, status) in expected {
            assert_eq!(class.code(), code);
            assert_eq!(class.exit_code(), status);
        }
        assert_eq!(RunCategory::Normal.exit_class(), ExitClass::Success);
        assert_eq!(
            RunCategory::SampleFailure.exit_class(),
            ExitClass::SampleFailure
        );
        assert_eq!(RunCategory::Fatal.exit_class(), ExitClass::Fatal);
        assert_eq!(RunCategory::Remote.exit_class(), ExitClass::RemoteFailure);
    }

    #[test]
    fn all_short_and_long_options_parse_with_values_or_flags() {
        let invocation = parse_ok(&[
            "-?",
            "-h",
            "-v",
            "-p",
            "p",
            "-q",
            "q",
            "-t",
            "t",
            "-l",
            "l",
            "-i",
            "i",
            "-j",
            "j",
            "-n",
            "-E",
            "http",
            "-H",
            "host",
            "-P",
            "8080",
            "-N",
            "localhost",
            "-u",
            "user",
            "-a",
            "secret",
            "-J",
            "one=1",
            "-G",
            "two=2",
            "-D",
            "three=3",
            "-S",
            "system",
            "-f",
            "-L",
            "DEBUG",
            "-r",
            "-R",
            "one,two",
            "-d",
            "home",
            "-X",
            "-e",
            "-o",
            "out",
        ]);
        assert_eq!(invocation.options.occurrences.len(), 28);
        assert_eq!(invocation.options.proxy.password.as_deref(), Some("secret"));
    }

    #[test]
    fn repeatable_values_keep_exact_order_and_equals_after_first() {
        let invocation = parse_ok(&[
            "-n",
            "-t",
            "plan.jmx",
            "-l",
            "result.jtl",
            "-qfirst",
            "-q",
            "second",
            "-Jx=a=b",
            "--jmeterproperty",
            "y=☃",
            "-Gfile.properties",
            "-Gz=last",
            "-Dk=v",
            "-Dk=last",
            "-Sone",
            "--systemPropertyFile=two",
            "-Lfoo=DEBUG",
            "-LINFO",
        ]);
        assert_eq!(invocation.options.addprop, ["first", "second"]);
        assert_eq!(invocation.options.jmeter_properties[0].raw, "x=a=b");
        assert_eq!(invocation.options.jmeter_properties[1].value, "☃");
        assert_eq!(invocation.options.system_property_files, ["one", "two"]);
        assert_eq!(
            invocation
                .options
                .occurrences
                .iter()
                .filter(|occurrence| occurrence.id == OptionId::Jmeterproperty)
                .map(|occurrence| occurrence.value())
                .collect::<Vec<_>>(),
            vec![Some("x=a=b"), Some("y=☃")]
        );
    }

    #[test]
    fn long_equals_and_attached_short_forms_are_equivalent() {
        let separate = parse_ok(&["-n", "-t", "plan", "-l", "result", "-J", "x=y"]);
        let attached = parse_ok(&[
            "--nongui",
            "--testfile=plan",
            "--logfile=result",
            "--jmeterproperty=x=y",
        ]);
        assert_eq!(separate.options.mode, attached.options.mode);
        assert_eq!(separate.options.testfile, attached.options.testfile);
        assert_eq!(separate.options.logfile, attached.options.logfile);
        assert_eq!(
            separate.options.jmeter_properties,
            attached.options.jmeter_properties
        );
    }

    #[test]
    fn http_selector_accepts_only_direct_native_forms_and_preserves_absent_provider() {
        let attached = parse_ok(&["-Jjmeter-rs.http.capability=http.native/1"]);
        assert_eq!(
            attached.resolve_http_capability_selector(),
            Ok(HttpCapabilitySelector::NativeV1)
        );
        assert_eq!(
            resolve_http_capability_selector(&attached),
            Ok(HttpCapabilitySelector::NativeV1)
        );

        let separate = parse_ok(&["-J", "jmeter-rs.http.capability=http.native/1"]);
        assert_eq!(
            separate.resolve_http_capability_selector(),
            Ok(HttpCapabilitySelector::NativeV1)
        );

        let attached_v2 = parse_ok(&["-Jjmeter-rs.http.capability=http.native/2"]);
        assert_eq!(
            attached_v2.resolve_http_capability_selector(),
            Ok(HttpCapabilitySelector::NativeV2)
        );
        let separate_v2 = parse_ok(&["-J", "jmeter-rs.http.capability=http.native/2"]);
        assert_eq!(
            separate_v2.resolve_http_capability_selector(),
            Ok(HttpCapabilitySelector::NativeV2)
        );
        assert!(HttpCapabilitySelector::NativeV1.is_native());
        assert!(HttpCapabilitySelector::NativeV1.is_native_v1());
        assert!(!HttpCapabilitySelector::NativeV1.is_native_v2());
        assert!(HttpCapabilitySelector::NativeV2.is_native());
        assert!(!HttpCapabilitySelector::NativeV2.is_native_v1());
        assert!(HttpCapabilitySelector::NativeV2.is_native_v2());

        // The direct selector is order-independent relative to unrelated
        // repeatable `-J` properties, which must not become conflicts.
        let selector_last = parse_ok(&[
            "-J",
            "ordinary.before=value",
            "-J",
            "jmeter-rs.http.capability=http.native/1",
        ]);
        let selector_first = parse_ok(&[
            "-Jjmeter-rs.http.capability=http.native/1",
            "-Jordinary.after=value",
        ]);
        assert_eq!(
            resolve_http_capability_selector(&selector_last),
            Ok(HttpCapabilitySelector::NativeV1)
        );
        assert_eq!(
            resolve_http_capability_selector(&selector_first),
            Ok(HttpCapabilitySelector::NativeV1)
        );

        let no_selector = parse_ok(&[]);
        assert_eq!(
            no_selector.resolve_http_capability_selector(),
            Ok(HttpCapabilitySelector::Absent)
        );
        assert!(!HttpCapabilitySelector::Absent.is_native());
        assert!(!HttpCapabilitySelector::Absent.is_native_v1());
        assert!(!HttpCapabilitySelector::Absent.is_native_v2());
        assert_eq!(HttpCapabilitySelector::Absent.as_str(), "absent");

        let unrelated = parse_ok(&["-J", "ordinary=value"]);
        assert_eq!(
            resolve_http_capability_selector(&unrelated),
            Ok(HttpCapabilitySelector::Absent)
        );

        // File source contents are intentionally not observable from this
        // pure API, so selecting a file does not authorize NativeV1 or create
        // a false selector error.
        for invocation in [
            parse_ok(&["-p", "primary.properties"]),
            parse_ok(&["-q", "additional.properties"]),
            parse_ok(&["-S", "system.properties"]),
        ] {
            assert_eq!(
                resolve_http_capability_selector(&invocation),
                Ok(HttpCapabilitySelector::Absent)
            );
        }
    }

    #[test]
    fn http_selector_rejects_repeated_empty_removed_and_unknown_values() {
        let repeated = parse_ok(&[
            "-J",
            "jmeter-rs.http.capability=http.native/1",
            "-Jjmeter-rs.http.capability=http.native/2",
        ])
        .resolve_http_capability_selector()
        .expect_err("repeated selector assignments must fail closed");
        assert!(matches!(
            repeated,
            HttpCapabilitySelectorError::Repeated { occurrences: 2 }
        ));
        assert_eq!(repeated.code(), "http.selector.repeated");
        assert_eq!(repeated.exit_class(), ExitClass::UsageError);
        assert_eq!(repeated.exit_code(), 2);

        for invocation in [
            parse_ok(&["-Jjmeter-rs.http.capability="]),
            parse_ok(&["-J", "jmeter-rs.http.capability"]),
        ] {
            let error = invocation
                .resolve_http_capability_selector()
                .expect_err("empty/removal selector assignments must fail closed");
            assert!(matches!(
                error,
                HttpCapabilitySelectorError::Empty {
                    source: HttpCapabilitySelectorSource::DirectJmeterProperty,
                }
            ));
            assert_eq!(error.code(), "http.selector.empty");
        }

        let unknown = parse_ok(&["-J", "jmeter-rs.http.capability=http.native/3"])
            .resolve_http_capability_selector()
            .expect_err("unknown capability values must fail closed");
        assert!(matches!(
            unknown,
            HttpCapabilitySelectorError::UnknownValue {
                source: HttpCapabilitySelectorSource::DirectJmeterProperty,
                ..
            }
        ));
        assert_eq!(unknown.code(), "http.selector.unknown");
        assert!(unknown.to_string().contains("http.native/3"));

        for value in ["http.native", "native/1", "HTTP.NATIVE/1"] {
            let argument = format!("{HTTP_CAPABILITY_SELECTOR_KEY}={value}");
            let error = parse_ok(&["-J", &argument])
                .resolve_http_capability_selector()
                .expect_err("selector aliases must not be accepted");
            assert!(matches!(
                error,
                HttpCapabilitySelectorError::UnknownValue {
                    source: HttpCapabilitySelectorSource::DirectJmeterProperty,
                    ..
                }
            ));
        }
    }

    #[test]
    fn direct_property_removal_forms_fail_closed_even_in_raw_occurrences() {
        let mut selector = parse_ok(&["-J", "ordinary=value"]);
        let occurrence = selector
            .options
            .occurrences
            .first_mut()
            .expect("direct occurrence");
        occurrence.value = Some(HTTP_CAPABILITY_SELECTOR_KEY.to_owned());
        let error = selector
            .resolve_http_capability_selector()
            .expect_err("raw selector removal must fail");
        assert!(matches!(
            error,
            HttpCapabilitySelectorError::Empty {
                source: HttpCapabilitySelectorSource::DirectJmeterProperty
            }
        ));

        let mut properties = parse_ok(&["-J", "ordinary=value"]);
        let occurrence = properties
            .options
            .occurrences
            .first_mut()
            .expect("direct occurrence");
        occurrence.value = Some(HTTP_DNS_NAMESERVERS_KEY.to_owned());
        let error = properties
            .resolve_http_native_v2_properties()
            .expect_err("raw NativeV2 removal must fail");
        assert!(matches!(
            error,
            HttpNativeV2PropertyError::Empty {
                property: HTTP_DNS_NAMESERVERS_KEY,
                source: HttpCapabilitySelectorSource::DirectJmeterProperty,
                ..
            }
        ));
    }

    #[test]
    fn http_selector_rejects_observable_non_direct_sources_and_redacts_values() {
        let system = parse_ok(&["-D", "jmeter-rs.http.capability=http.native/1"])
            .resolve_http_capability_selector()
            .expect_err("-D must not authorize the application-owned selector");
        assert!(matches!(
            system,
            HttpCapabilitySelectorError::NonDirectSource {
                source: HttpCapabilitySelectorSource::SystemProperty,
                ..
            }
        ));
        assert_eq!(system.code(), "http.selector.non-direct-source");

        let global = parse_ok(&["-G", "jmeter-rs.http.capability=http.native/1"])
            .resolve_http_capability_selector()
            .expect_err("-G must not authorize the application-owned selector");
        assert!(matches!(
            global,
            HttpCapabilitySelectorError::NonDirectSource {
                source: HttpCapabilitySelectorSource::GlobalProperty,
                ..
            }
        ));

        let system_v2 = parse_ok(&["-D", "jmeter-rs.http.capability=http.native/2"])
            .resolve_http_capability_selector()
            .expect_err("-D must not authorize the NativeV2 selector");
        assert!(matches!(
            &system_v2,
            HttpCapabilitySelectorError::NonDirectSource {
                source: HttpCapabilitySelectorSource::SystemProperty,
                value,
            } if value == HTTP_NATIVE_V2_CAPABILITY
        ));
        assert_eq!(system_v2.code(), "http.selector.non-direct-source");

        let empty_global = parse_ok(&["-G", "jmeter-rs.http.capability="])
            .resolve_http_capability_selector()
            .expect_err("an observable non-direct removal must fail closed");
        assert!(matches!(
            empty_global,
            HttpCapabilitySelectorError::NonDirectSource {
                source: HttpCapabilitySelectorSource::GlobalProperty,
                ..
            }
        ));

        let secret_like = parse_ok(&["-Jjmeter-rs.http.capability=topsecret"])
            .resolve_http_capability_selector()
            .expect_err("secret-like unknown values must fail closed");
        assert!(matches!(
            secret_like,
            HttpCapabilitySelectorError::UnknownValue { .. }
        ));
        assert!(!secret_like.to_string().contains("topsecret"));
        assert!(!format!("{secret_like:?}").contains("topsecret"));
        assert!(secret_like.to_string().contains("<redacted>"));
        assert!(format!("{secret_like:?}").contains("<redacted>"));
    }

    #[test]
    fn native_v2_properties_accept_exact_direct_forms_and_preserve_order_and_origin() {
        let invocation = parse_ok(&[
            "-J",
            "ordinary=before",
            "-Jjmeter-rs.http.dns.nameservers=1.1.1.1,[2001:db8::53]:53,192.0.2.10:53",
            "-J",
            "jmeter-rs.http.tls.ca-file=./certs/ca.pem",
        ]);
        let properties = invocation
            .resolve_http_native_v2_properties()
            .expect("valid NativeV2 properties");
        let nameservers = properties
            .dns_nameservers
            .as_ref()
            .expect("nameserver selection");
        assert_eq!(
            nameservers.nameservers,
            [
                "1.1.1.1:53".parse::<SocketAddr>().expect("IPv4"),
                "[2001:db8::53]:53".parse::<SocketAddr>().expect("IPv6"),
                "192.0.2.10:53".parse::<SocketAddr>().expect("IPv4 socket"),
            ]
        );
        assert_eq!(
            nameservers.origin.source,
            HttpCapabilitySelectorSource::DirectJmeterProperty
        );
        assert_eq!(nameservers.origin.occurrence, 2);

        let ca_file = properties.tls_ca_file.as_ref().expect("CA selection");
        assert_eq!(ca_file.path.as_str(), "./certs/ca.pem");
        assert_eq!(
            ca_file.origin.source,
            HttpCapabilitySelectorSource::DirectJmeterProperty
        );
        assert_eq!(ca_file.origin.occurrence, 3);
        assert_eq!(
            properties.nameservers(),
            Some(nameservers.nameservers.as_slice())
        );
        assert_eq!(
            properties.ca_file().map(HttpNativeV2CaFilePath::as_str),
            Some("./certs/ca.pem")
        );
    }

    #[test]
    fn native_v2_properties_are_optional_when_absent() {
        let absent = parse_ok(&[])
            .resolve_http_native_v2_properties()
            .expect("absent optional properties");
        assert!(absent.is_empty());
        assert_eq!(absent.dns_nameservers, None);
        assert_eq!(absent.tls_ca_file, None);

        let unrelated = parse_ok(&["-Jordinary=value"])
            .resolve_http_native_v2_properties()
            .expect("unrelated property");
        assert!(unrelated.is_empty());
    }

    #[test]
    fn native_v2_properties_reject_direct_repeats_and_non_direct_sources() {
        for (key, values) in [
            (HTTP_DNS_NAMESERVERS_KEY, "1.1.1.1:53,8.8.8.8:53"),
            (HTTP_TLS_CA_FILE_KEY, "first.pem"),
        ] {
            let argument = format!("{key}={values}");
            let repeated_argument = format!("{key}=second.pem");
            let invocation = parse_strings(vec![
                "-J".to_owned(),
                argument,
                "-J".to_owned(),
                repeated_argument,
            ])
            .expect("repeated property parses");
            let error = invocation
                .resolve_http_native_v2_properties()
                .expect_err("direct repeat must fail");
            assert!(matches!(
                error,
                HttpNativeV2PropertyError::Repeated { property, occurrences: 2 }
                    if property == key
            ));
            assert_eq!(error.code(), "http.native-v2.property.repeated");
        }

        for (option, source) in [
            ("-D", HttpCapabilitySelectorSource::SystemProperty),
            ("-G", HttpCapabilitySelectorSource::GlobalProperty),
        ] {
            let argument = format!("{HTTP_DNS_NAMESERVERS_KEY}=1.1.1.1:53");
            let invocation = parse_ok(&[option, &argument]);
            let error = invocation
                .resolve_http_native_v2_properties()
                .expect_err("non-direct DNS source must fail");
            assert!(matches!(
                error,
                HttpNativeV2PropertyError::NonDirectSource {
                    property: HTTP_DNS_NAMESERVERS_KEY,
                    source: actual,
                    occurrence: 0,
                } if actual == source
            ));
            assert_eq!(error.code(), "http.native-v2.property.non-direct-source");
        }

        let global_removal = parse_ok(&["-G", "jmeter-rs.http.tls.ca-file="]);
        let error = global_removal
            .resolve_http_native_v2_properties()
            .expect_err("observable global same-key removal must fail");
        assert!(matches!(
            error,
            HttpNativeV2PropertyError::NonDirectSource {
                property: HTTP_TLS_CA_FILE_KEY,
                source: HttpCapabilitySelectorSource::GlobalProperty,
                ..
            }
        ));
    }

    #[test]
    fn native_v2_nameservers_enforce_numeric_ports_whitespace_duplicates_and_bounds() {
        let invalid = [
            ("not-a-hostname", HttpNativeV2NameserverError::NonNumeric),
            ("[2001:db8::1", HttpNativeV2NameserverError::InvalidSocket),
            (
                "2001:db8::1:53",
                HttpNativeV2NameserverError::UnbracketedIpv6Port,
            ),
            (
                "1.1.1.1:54",
                HttpNativeV2NameserverError::PortNot53 { port: 54 },
            ),
            ("1.1.1.1:0", HttpNativeV2NameserverError::Zero),
            ("0.0.0.0", HttpNativeV2NameserverError::Zero),
            ("1.1.1.1,", HttpNativeV2NameserverError::EmptyEntry),
            ("1.1.1.1, 8.8.8.8", HttpNativeV2NameserverError::Whitespace),
            ("1.1.1.1:53,1.1.1.1", HttpNativeV2NameserverError::Duplicate),
        ];
        for (value, reason) in invalid {
            let argument = format!("{HTTP_DNS_NAMESERVERS_KEY}={value}");
            let error = parse_ok(&["-J", &argument])
                .resolve_http_native_v2_properties()
                .expect_err("invalid nameserver must fail");
            assert!(matches!(
                error,
                HttpNativeV2PropertyError::InvalidNameservers { reason: actual, .. }
                    if actual == reason
            ));
        }

        let exactly_max = (1..=MAX_HTTP_NATIVE_V2_NAMESERVERS)
            .map(|octet| format!("192.0.2.{octet}"))
            .collect::<Vec<_>>()
            .join(",");
        let argument = format!("{HTTP_DNS_NAMESERVERS_KEY}={exactly_max}");
        let properties = parse_ok(&["-J", &argument])
            .resolve_http_native_v2_properties()
            .expect("maximum nameserver list is accepted");
        assert_eq!(
            properties
                .dns_nameservers
                .as_ref()
                .expect("nameservers")
                .nameservers
                .len(),
            MAX_HTTP_NATIVE_V2_NAMESERVERS
        );

        let over_max = (1..=MAX_HTTP_NATIVE_V2_NAMESERVERS + 1)
            .map(|octet| format!("198.51.100.{octet}"))
            .collect::<Vec<_>>()
            .join(",");
        let argument = format!("{HTTP_DNS_NAMESERVERS_KEY}={over_max}");
        let error = parse_ok(&["-J", &argument])
            .resolve_http_native_v2_properties()
            .expect_err("too many nameservers must fail");
        assert!(matches!(
            error,
            HttpNativeV2PropertyError::InvalidNameservers {
                reason: HttpNativeV2NameserverError::TooMany { count: 17 },
                ..
            }
        ));

        assert_eq!(
            HttpCapabilitySelectorError::OccurrenceOverflow {
                source: HttpCapabilitySelectorSource::DirectJmeterProperty,
            }
            .code(),
            "http.selector.occurrence-overflow"
        );
        assert_eq!(
            HttpNativeV2PropertyError::OccurrenceOverflow {
                property: HTTP_DNS_NAMESERVERS_KEY,
            }
            .code(),
            "http.native-v2.property.occurrence-overflow"
        );
    }

    #[test]
    fn native_v2_properties_reject_empty_removed_oversized_and_malformed_ca_paths() {
        for argument in [
            format!("{HTTP_DNS_NAMESERVERS_KEY}="),
            format!("{HTTP_TLS_CA_FILE_KEY}="),
        ] {
            let error = parse_ok(&["-J", &argument])
                .resolve_http_native_v2_properties()
                .expect_err("empty direct property must fail");
            assert!(matches!(error, HttpNativeV2PropertyError::Empty { .. }));
        }

        let oversized = "x".repeat(MAX_HTTP_NATIVE_V2_PROPERTY_BYTES + 1);
        let argument = format!("{HTTP_TLS_CA_FILE_KEY}={oversized}");
        let error = parse_ok(&["-J", &argument])
            .resolve_http_native_v2_properties()
            .expect_err("oversized CA path must fail before copy");
        assert!(matches!(
            &error,
            HttpNativeV2PropertyError::ValueTooLong {
                property: HTTP_TLS_CA_FILE_KEY,
                observed,
                limit: MAX_HTTP_NATIVE_V2_PROPERTY_BYTES,
                ..
            } if *observed == MAX_HTTP_NATIVE_V2_PROPERTY_BYTES + 1
        ));
        assert_eq!(error.occurrence(), Some(0));

        for (path, reason) in [
            ("/tmp/ca.pem", HttpNativeV2CaPathError::Absolute),
            ("../ca.pem", HttpNativeV2CaPathError::Parent),
            ("certs/../ca.pem", HttpNativeV2CaPathError::Parent),
            ("..\\ca.pem", HttpNativeV2CaPathError::Parent),
            ("\\ca.pem", HttpNativeV2CaPathError::Root),
            ("C:\\ca.pem", HttpNativeV2CaPathError::Prefix),
            ("\\\\server\\share\\ca.pem", HttpNativeV2CaPathError::Prefix),
        ] {
            let argument = format!("{HTTP_TLS_CA_FILE_KEY}={path}");
            let error = parse_ok(&["-J", &argument])
                .resolve_http_native_v2_properties()
                .expect_err("unsafe CA path must fail");
            assert!(matches!(
                error,
                HttpNativeV2PropertyError::InvalidCaFile { reason: actual, .. }
                    if actual == reason
            ));
        }

        let nul = format!("{HTTP_TLS_CA_FILE_KEY}=cert\0.pem");
        let error = parse_ok(&["-J", &nul])
            .resolve_http_native_v2_properties()
            .expect_err("NUL CA path must fail");
        assert!(matches!(
            error,
            HttpNativeV2PropertyError::InvalidCaFile {
                reason: HttpNativeV2CaPathError::Nul,
                ..
            }
        ));
    }

    #[test]
    fn native_v2_property_diagnostics_redact_values_and_ca_paths() {
        let secret_nameserver = "203.0.113.77:54";
        let argument = format!("{HTTP_DNS_NAMESERVERS_KEY}={secret_nameserver}");
        let error = parse_ok(&["-J", &argument])
            .resolve_http_native_v2_properties()
            .expect_err("invalid nameserver");
        let display = error.to_string();
        let debug = format!("{error:?}");
        assert!(!display.contains(secret_nameserver));
        assert!(!debug.contains(secret_nameserver));
        assert!(display.contains("<redacted>"));

        let secret_path = "../private-ca.pem";
        let argument = format!("{HTTP_TLS_CA_FILE_KEY}={secret_path}");
        let error = parse_ok(&["-J", &argument])
            .resolve_http_native_v2_properties()
            .expect_err("unsafe CA path");
        let display = error.to_string();
        let debug = format!("{error:?}");
        assert!(!display.contains(secret_path));
        assert!(!debug.contains(secret_path));
        assert!(display.contains("<redacted>"));

        let accepted = parse_ok(&["-J", "jmeter-rs.http.tls.ca-file=private-ca.pem"])
            .resolve_http_native_v2_properties()
            .expect("valid CA path");
        let debug = format!("{accepted:?}");
        assert!(!debug.contains("private-ca.pem"));
    }

    #[test]
    fn last_is_preserved_and_marked_only_for_plan_and_logs() {
        let invocation = parse_ok(&["-t", "LAST", "-l", "LAST.jtl", "-jLAST.log"]);
        assert!(
            invocation
                .options
                .testfile
                .as_ref()
                .is_some_and(PathArgument::is_last)
        );
        assert!(
            invocation
                .options
                .logfile
                .as_ref()
                .is_some_and(PathArgument::is_last)
        );
        assert!(
            invocation
                .options
                .jmeterlogfile
                .as_ref()
                .is_some_and(PathArgument::is_last)
        );
        let recent = Path::new("/tmp/RecentPlan.JmX");
        assert_eq!(
            invocation
                .options
                .logfile
                .as_ref()
                .and_then(|path| path.resolve_last_against(recent, ".jtl")),
            Some(PathBuf::from("/tmp/RecentPlan.jtl"))
        );
        assert_eq!(
            invocation
                .options
                .jmeterlogfile
                .as_ref()
                .and_then(|path| path.resolve_last_against(recent, ".log")),
            Some(PathBuf::from("LAST.log"))
        );
        let report = parse_ok(&["-g", "LAST"]);
        assert_eq!(report.options.report_only_file.as_deref(), Some("LAST"));
    }

    #[test]
    fn unicode_values_and_keys_are_not_normalized() {
        let invocation = parse_ok(&[
            "--nongui",
            "--testfile",
            "测试计划.jmx",
            "--logfile",
            "résultat.jtl",
            "--jmeterproperty",
            "ключ=значение=☃",
        ]);
        assert_eq!(
            invocation
                .options
                .testfile
                .as_ref()
                .map(PathArgument::as_str),
            Some("测试计划.jmx")
        );
        assert_eq!(
            invocation.options.jmeter_properties[0].raw,
            "ключ=значение=☃"
        );
    }

    #[test]
    fn malformed_values_are_typed_and_stable() {
        let removal = parse_ok(&["-J", "missing"]);
        assert_eq!(removal.options.jmeter_properties[0].raw, "missing=");
        for argument in ["-J=", "-D=", "-G=", "-L="] {
            assert!(matches!(
                parse_ok_err(&[argument]),
                CliError::InvalidValue {
                    reason: ValueError::Empty,
                    ..
                }
            ));
        }
        let missing = parse_ok_err(&["--testfile"]);
        assert!(matches!(
            missing,
            CliError::MissingValue {
                option: OptionId::Testfile,
                ..
            }
        ));
        let unknown = parse_ok_err(&["--not-an-option"]);
        assert_eq!(unknown.exit_code(), 2);
    }

    #[test]
    fn cli_diagnostics_redact_sensitive_unknown_and_argument_tokens() {
        let typo = parse_ok_err(&["--passwrod=secret"]);
        assert_eq!(typo.code(), "cli.unknown-option");
        let typo_display = typo.to_string();
        let typo_debug = format!("{typo:?}");
        assert!(typo_display.contains("--passwrod"));
        assert!(typo_display.contains(REDACTED_CLI_VALUE));
        assert!(!typo_display.contains("secret"));
        assert!(typo_debug.contains("--passwrod"));
        assert!(typo_debug.contains(REDACTED_CLI_VALUE));
        assert!(!typo_debug.contains("secret"));

        let attached_password = CliError::UnknownOption {
            token: "--password=secret".to_owned(),
        };
        assert_eq!(attached_password.code(), "cli.unknown-option");
        assert!(attached_password.to_string().contains("--password"));
        assert!(!attached_password.to_string().contains("secret"));

        let secretish = CliError::UnknownOption {
            token: "--typo=topsecret".to_owned(),
        };
        assert!(secretish.to_string().contains("--typo"));
        assert!(!secretish.to_string().contains("topsecret"));

        let positional = parse_ok_err(&["--", "password=secret"]);
        assert_eq!(positional.code(), "cli.unexpected-argument");
        assert!(positional.to_string().contains("password"));
        assert!(!positional.to_string().contains("secret"));
        assert!(!format!("{positional:?}").contains("secret"));

        let duplicate = parse_ok_err(&["--password=first", "--password=second"]);
        assert_eq!(duplicate.code(), "cli.duplicate-option");
        assert!(duplicate.to_string().contains("--password"));
        assert!(!duplicate.to_string().contains("second"));
        assert!(!format!("{duplicate:?}").contains("second"));

        let malformed_property = CliError::InvalidValue {
            option: OptionId::Jmeterproperty,
            value: "http.proxyPass=secret".to_owned(),
            reason: ValueError::MissingAssignment,
        };
        assert!(malformed_property.to_string().contains("--jmeterproperty"));
        assert!(!malformed_property.to_string().contains("secret"));
        assert!(!format!("{malformed_property:?}").contains("secret"));

        let ordinary = parse_ok_err(&["--typo=value"]);
        assert!(ordinary.to_string().contains("--typo=value"));
    }

    #[test]
    fn property_and_loglevel_separate_forms_consume_exactly_one_token() {
        for option in ["-J", "-G", "-D", "-L"] {
            let error = parse_ok_err(&[option, "key=value", "orphan"]);
            assert!(matches!(
                error,
                CliError::UnexpectedArgument { argument } if argument == "orphan"
            ));
        }
        let property = parse_ok(&["-J", "key=value"]);
        assert_eq!(property.options.jmeter_properties[0].raw, "key=value");
        let loglevel = parse_ok(&["-L", "org.apache.jmeter=DEBUG"]);
        assert_eq!(
            loglevel.options.log_levels[0].raw,
            "org.apache.jmeter=DEBUG"
        );
    }

    fn parse_ok_err(arguments: &[&str]) -> CliError {
        parse(arguments.iter().map(|value| (*value).to_owned())).expect_err("arguments fail")
    }

    #[test]
    fn mode_and_report_combinations_are_rejected() {
        assert!(matches!(
            parse_ok_err(&["-n"]),
            CliError::IncompatibleOptions {
                reason: CombinationError::NonGuiNeedsTestfile,
                ..
            }
        ));
        assert!(matches!(
            parse_ok_err(&["-n", "-t", "plan", "-e"]),
            CliError::IncompatibleOptions {
                reason: CombinationError::ReportAtEndNeedsLogfile,
                ..
            }
        ));
        assert!(
            parse_ok(&["-n", "-t", "plan", "-l", "result", "-e"])
                .options
                .report_at_end
        );
        for arguments in [
            vec!["-g", "input.jtl", "-t", "plan"],
            vec!["-t", "plan", "-g", "input.jtl"],
        ] {
            assert!(matches!(
                parse_ok_err(&arguments),
                CliError::IncompatibleOptions {
                    reason: CombinationError::ReportOnlyNeedsOnlyJtl,
                    ..
                }
            ));
        }
        let report_with_end = parse_ok(&["-g", "input.jtl", "-e", "-o", "out"]);
        assert!(report_with_end.options.report_at_end);
        assert!(
            parse_ok(&["-g", "input.jtl", "-X"])
                .options
                .remote
                .remote_exit
        );
        assert!(matches!(
            parse_ok_err(&["-o", "out"]),
            CliError::IncompatibleOptions {
                reason: CombinationError::ReportOutputNeedsReport,
                ..
            }
        ));
        assert!(
            parse_ok(&["-n", "-t", "plan", "-X"])
                .options
                .remote
                .remote_exit
        );
        assert!(matches!(
            parse_ok_err(&["-X"]),
            CliError::IncompatibleOptions {
                reason: CombinationError::RemoteNeedsNonGui,
                ..
            }
        ));
        for arguments in [
            vec!["-g", "input.jtl", "-n"],
            vec!["-g", "input.jtl", "-r"],
            vec!["-g", "input.jtl", "-R", "host"],
            vec!["-g", "input.jtl", "-l", "result.jtl"],
        ] {
            assert!(matches!(
                parse_ok_err(&arguments),
                CliError::IncompatibleOptions { .. }
            ));
        }
    }

    #[test]
    fn configuration_plan_is_ordered_and_has_no_io() {
        let invocation = parse_ok(&[
            "-p",
            "primary",
            "-j",
            "run.log",
            "-q",
            "additional",
            "-J",
            "local=value",
            "-G",
            "global=value",
            "-D",
            "system=value",
            "-S",
            "system-file",
            "-L",
            "root=DEBUG",
            "-n",
            "-t",
            "plan",
            "-l",
            "result",
        ]);
        let steps = invocation.configuration.steps();
        assert!(matches!(
            steps[0],
            ConfigurationStep::LoadProperties {
                source: PropertySource::ExplicitPrimary { .. }
            }
        ));
        assert!(matches!(
            steps[1],
            ConfigurationStep::SelectJmeterLog { .. }
        ));
        assert!(matches!(
            steps[2],
            ConfigurationStep::InitializeLogging { .. }
        ));
        assert!(matches!(
            steps[3],
            ConfigurationStep::LoadUserProperties { .. }
        ));
        assert!(matches!(
            steps[4],
            ConfigurationStep::LoadSystemProperties { .. }
        ));
        let property_steps = invocation
            .configuration
            .property_steps()
            .collect::<Vec<_>>();
        assert!(property_steps.iter().any(|step| matches!(
            step,
            ConfigurationStep::LoadProperties {
                source: PropertySource::AdditionalJmeter { .. }
            }
        )));
        assert!(matches!(
            property_steps.last(),
            Some(ConfigurationStep::ApplyLogLevel { .. })
        ));
        assert!(matches!(
            steps.last(),
            Some(ConfigurationStep::SelectInputs { .. })
        ));
    }

    #[test]
    fn proxy_password_is_redacted_from_debug_and_display() {
        let invocation = parse_ok(&["-a", "super-secret", "-J", "http.proxyPass=other-secret"]);
        let debug = format!("{:?}", invocation);
        let display = invocation.to_string();
        assert!(!debug.contains("super-secret"));
        assert!(!debug.contains("other-secret"));
        assert!(!display.contains("super-secret"));
        assert!(debug.contains("<redacted>"));
        assert!(display.contains("<redacted>"));
        assert_eq!(
            invocation.options.proxy.password.as_deref(),
            Some("super-secret")
        );
    }

    #[test]
    fn help_and_version_actions_skip_execution_combination_checks() {
        let help = parse_ok(&["--help", "-n"]);
        assert_eq!(help.action, Action::Help);
        let version = parse_ok(&["--version", "-n"]);
        assert_eq!(version.action, Action::Version);
        assert!(help_text().contains("To run Apache JMeter in NON_GUI mode"));
        assert!(options_text().contains("--systemPropertyFile"));
        assert!(options_text().contains("-?, --?"));
        assert!(version_text().contains("5.6.3"));
        assert!(matches!(
            parse_ok_err(&["--version", "-H", "proxy"]),
            CliError::IncompatibleOptions {
                reason: CombinationError::ProxyNeedsHostAndPort,
                ..
            }
        ));
    }

    #[test]
    fn terminator_and_positionals_fail_closed() {
        let terminator = parse_ok(&["--"]);
        assert!(terminator.options.option_terminator);
        assert!(matches!(
            parse_ok_err(&["--", "-n"]),
            CliError::UnexpectedArgument { argument } if argument == "-n"
        ));
        assert!(matches!(
            parse_ok_err(&["plan.jmx"]),
            CliError::UnexpectedArgument { argument } if argument == "plan.jmx"
        ));
    }

    #[test]
    fn non_unicode_os_argument_is_an_explicit_error() {
        #[cfg(unix)]
        let argument = OsString::from_vec(vec![0xff]);
        #[cfg(unix)]
        let error = parse_os([argument]).expect_err("invalid unicode must fail");
        #[cfg(unix)]
        assert_eq!(error, CliError::NonUnicodeArgument);
    }

    #[test]
    fn duplicate_singletons_are_rejected_but_repeats_are_allowed() {
        assert!(matches!(
            parse_ok_err(&["-t", "one", "-t", "two"]),
            CliError::DuplicateOption {
                option: OptionId::Testfile,
                ..
            }
        ));
        assert!(parse_ok(&["-q", "one", "-q", "two"]).options.addprop == ["one", "two"]);
    }
}
