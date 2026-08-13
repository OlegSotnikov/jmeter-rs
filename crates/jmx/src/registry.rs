// SPDX-License-Identifier: Apache-2.0
//! Pinned, data-only JMeter SaveService alias and upgrade registries.
//!
//! The tables in `../data` are generated from the Apache JMeter 5.6.3 source
//! snapshot named in the compatibility profile.  This module only maps wire
//! names to other wire names.  It never loads, reflects, or executes a class.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

const SAVESERVICE_5_6_3: &str = include_str!("../data/saveservice-5.6.3.properties");
const UPGRADE_5_6_3: &str = include_str!("../data/upgrade-5.6.3.properties");

/// The pinned upstream registry provenance.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RegistryVersion {
    /// Registry vocabulary version (`5.0` for JMeter 5.6.3).
    pub save_service_version: &'static str,
    /// JMeter release represented by the table.
    pub jmeter_version: &'static str,
    /// Upstream source commit used to generate the table.
    pub source_commit: &'static str,
    /// Relative path of the source table in this crate.
    pub source_path: &'static str,
}

impl RegistryVersion {
    /// Pinned Apache JMeter 5.6.3 registry metadata.
    pub const JMETER_5_6_3: Self = Self {
        save_service_version: "5.0",
        jmeter_version: "5.6.3",
        source_commit: "34a2785748e9e0b14702595e8682c387869deda3",
        source_path: "crates/jmx/data/saveservice-5.6.3.properties",
    };

    /// Exact active alias count in the pinned SaveService table.
    pub const JMETER_5_6_3_ALIAS_COUNT: usize = 293;
    /// Exact primary-class count in the pinned SaveService table.
    pub const JMETER_5_6_3_PRIMARY_ALIAS_COUNT: usize = 290;
    /// Exact active rule count in the pinned upgrade table.
    pub const JMETER_5_6_3_UPGRADE_RULE_COUNT: usize = 52;
    /// SHA-256 of the embedded SaveService table, including provenance
    /// comments and line endings.
    pub const JMETER_5_6_3_SAVESERVICE_SHA256: &'static str =
        "eca06d3b962db3966e91f5670e1d28e9b1b08b4c82cd52f2730a4eb80da838e2";
    /// SHA-256 of the embedded upgrade table, including provenance comments
    /// and line endings.
    pub const JMETER_5_6_3_UPGRADE_SHA256: &'static str =
        "ca4be70124d06d75425d25e5993a587d7263e4561563395c82d1fb002568b831";

    /// Returns the pinned profile identifier.
    #[must_use]
    pub const fn profile_id(self) -> &'static str {
        "jmeter-5.6.3"
    }
}

/// A data-only alias lookup result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AliasResolution {
    /// The input alias or class name.
    pub input: String,
    /// Fully qualified upstream class name, when the alias is known.
    pub class_name: Option<String>,
    /// Primary alias selected for canonical output, when known.
    pub primary_alias: Option<String>,
}

impl AliasResolution {
    /// Returns whether the input was found in the pinned table.
    #[must_use]
    pub fn is_known(&self) -> bool {
        self.class_name.is_some()
    }
}

/// Errors found while loading a registry table.
#[derive(Clone, Eq, PartialEq)]
pub enum RegistryError {
    /// A line had no key or value.
    MalformedLine {
        /// One-based source line number.
        line: usize,
    },
    /// Two aliases had different class targets.
    ConflictingAlias {
        /// Alias with conflicting targets.
        alias: String,
    },
    /// Two classes requested different primary aliases.
    ConflictingPrimary {
        /// Class with conflicting primary aliases.
        class_name: String,
    },
    /// Two upgrade entries declared different targets for one exact rule key.
    ConflictingUpgrade {
        /// Stable textual key identifying the conflicting rule.
        key: String,
    },
    /// A profile has no pinned table in this crate.
    UnsupportedProfile {
        /// Requested profile identifier.
        profile_id: String,
    },
}

impl fmt::Debug for RegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegistryError")
            .field("code", &self.code())
            .finish()
    }
}

impl RegistryError {
    /// Returns a stable diagnostic code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::MalformedLine { .. } => "jmx.registry.malformed-line",
            Self::ConflictingAlias { .. } => "jmx.registry.conflicting-alias",
            Self::ConflictingPrimary { .. } => "jmx.registry.conflicting-primary",
            Self::ConflictingUpgrade { .. } => "jmx.registry.conflicting-upgrade",
            Self::UnsupportedProfile { .. } => "jmx.registry.unsupported-profile",
        }
    }
}

impl fmt::Display for RegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedLine { line } => write!(formatter, "registry line {line} is malformed"),
            Self::ConflictingAlias { .. } => {
                formatter.write_str("registry contains conflicting alias targets")
            }
            Self::ConflictingPrimary { .. } => {
                formatter.write_str("registry contains conflicting primary aliases")
            }
            Self::ConflictingUpgrade { .. } => {
                formatter.write_str("registry contains conflicting upgrade targets")
            }
            Self::UnsupportedProfile { .. } => {
                formatter.write_str("requested registry profile is unsupported")
            }
        }
    }
}

impl std::error::Error for RegistryError {}

/// A versioned SaveService alias table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AliasRegistry {
    version: RegistryVersion,
    aliases: BTreeMap<String, String>,
    primary_aliases: BTreeMap<String, String>,
    // `Default` cannot return a `Result`.  Keep an embedded-table parse
    // failure attached to the value so callers can surface it through
    // `validate` instead of silently operating with an empty registry.
    load_error: Option<RegistryError>,
}

impl AliasRegistry {
    /// Loads a registry for a profile identifier currently supported by this
    /// crate. Only `jmeter-5.6.3` is pinned in the initial profile.
    pub fn for_profile(profile_id: &str) -> std::result::Result<Self, RegistryError> {
        if profile_id == RegistryVersion::JMETER_5_6_3.profile_id() {
            Self::jmeter_5_6_3()
        } else {
            Err(RegistryError::UnsupportedProfile {
                profile_id: profile_id.to_owned(),
            })
        }
    }

    /// Loads the pinned JMeter 5.6.3 table embedded in this crate.
    pub fn jmeter_5_6_3() -> std::result::Result<Self, RegistryError> {
        Self::from_properties(SAVESERVICE_5_6_3, RegistryVersion::JMETER_5_6_3)
    }

    /// Parses a SaveService-style table for a caller-selected version.
    ///
    /// This is intentionally a parser for data, not a class loader.  It is
    /// useful for future profile tables while the default remains pinned.
    pub fn from_properties(
        source: &str,
        version: RegistryVersion,
    ) -> std::result::Result<Self, RegistryError> {
        let mut aliases = BTreeMap::new();
        let mut primary_aliases = BTreeMap::new();
        for (line_index, raw_line) in source.lines().enumerate() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
                continue;
            }
            let Some((raw_key, raw_value)) = line.split_once('=') else {
                return Err(RegistryError::MalformedLine {
                    line: line_index + 1,
                });
            };
            let value = raw_value.trim();
            let key = raw_key.trim();
            if key.is_empty() {
                return Err(RegistryError::MalformedLine {
                    line: line_index + 1,
                });
            }
            if key.starts_with('_') {
                // `_version`, `_file_encoding`, and converter registrations
                // are SaveService metadata, not aliases.
                continue;
            }
            if value.is_empty() {
                return Err(RegistryError::MalformedLine {
                    line: line_index + 1,
                });
            }
            for (position, alias_part) in key.split(',').enumerate() {
                let alias = alias_part.trim();
                if alias.is_empty() {
                    return Err(RegistryError::MalformedLine {
                        line: line_index + 1,
                    });
                }
                if let Some(existing) = aliases.get(alias)
                    && existing != value
                {
                    return Err(RegistryError::ConflictingAlias {
                        alias: alias.to_owned(),
                    });
                }
                aliases.insert(alias.to_owned(), value.to_owned());
                if position == 0 {
                    if let Some(existing) = primary_aliases.get(value)
                        && existing != alias
                    {
                        return Err(RegistryError::ConflictingPrimary {
                            class_name: value.to_owned(),
                        });
                    }
                    primary_aliases.insert(value.to_owned(), alias.to_owned());
                }
            }
        }
        Ok(Self {
            version,
            aliases,
            primary_aliases,
            load_error: None,
        })
    }

    /// Validates that the embedded or caller-provided table loaded cleanly.
    pub fn validate(&self) -> std::result::Result<(), RegistryError> {
        self.load_error.clone().map_or(Ok(()), Err)
    }

    fn invalid(version: RegistryVersion, error: RegistryError) -> Self {
        Self {
            version,
            aliases: BTreeMap::new(),
            primary_aliases: BTreeMap::new(),
            load_error: Some(error),
        }
    }

    /// Returns provenance metadata for this table.
    #[must_use]
    pub const fn version(&self) -> RegistryVersion {
        self.version
    }

    /// Returns the fully qualified class for an alias.
    #[must_use]
    pub fn class_for_alias(&self, alias: &str) -> Option<&str> {
        self.aliases.get(alias).map(String::as_str)
    }

    /// Returns the primary alias for a fully qualified class.
    #[must_use]
    pub fn primary_alias_for_class(&self, class_name: &str) -> Option<&str> {
        self.primary_aliases.get(class_name).map(String::as_str)
    }

    /// Resolves either an alias or a fully qualified class name.
    #[must_use]
    pub fn resolve(&self, input: &str) -> AliasResolution {
        let class_name = self.class_for_alias(input).map(str::to_owned).or_else(|| {
            self.primary_aliases
                .contains_key(input)
                .then(|| input.to_owned())
        });
        let primary_alias = class_name
            .as_deref()
            .and_then(|class| self.primary_alias_for_class(class))
            .map(str::to_owned);
        AliasResolution {
            input: input.to_owned(),
            class_name,
            primary_alias,
        }
    }

    /// Returns all aliases in lexical order.
    pub fn aliases(&self) -> impl Iterator<Item = (&str, &str)> {
        self.aliases
            .iter()
            .map(|(alias, class_name)| (alias.as_str(), class_name.as_str()))
    }

    /// Returns the number of accepted aliases in the table.
    #[must_use]
    pub fn alias_count(&self) -> usize {
        self.aliases.len()
    }

    /// Returns the number of classes with a primary alias.
    #[must_use]
    pub fn primary_alias_count(&self) -> usize {
        self.primary_aliases.len()
    }

    /// Selects the canonical alias for a wire tag and test class.
    #[must_use]
    pub fn canonical_alias(&self, wire_tag: &str, test_class: &str) -> String {
        self.resolve(test_class)
            .primary_alias
            .or_else(|| self.resolve(wire_tag).primary_alias)
            .unwrap_or_else(|| wire_tag.to_owned())
    }
}

impl Default for AliasRegistry {
    fn default() -> Self {
        Self::jmeter_5_6_3()
            .unwrap_or_else(|error| Self::invalid(RegistryVersion::JMETER_5_6_3, error))
    }
}

/// A class/property/value upgrade rule from JMeter's `upgrade.properties`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UpgradeRule {
    /// Rename a test class.
    Class {
        /// Historical class name.
        old: String,
        /// Current class name.
        new: String,
    },
    /// Rename a test class when its historical GUI class also matches.
    ///
    /// The pinned `upgrade.properties` grammar is
    /// `old.class|old.gui=new.class`. The right-hand side is the replacement
    /// test class, not a GUI class.
    ClassAndGui {
        /// Historical test class name.
        old_class: String,
        /// Historical GUI class name.
        old_gui: String,
        /// Current test class name.
        new_class: String,
    },
    /// Rename or delete a property. `new` is `None` for deletion.
    Property {
        /// Test class owning the property.
        class_name: String,
        /// Historical property name.
        old: String,
        /// Current property name, or `None` when intentionally deleted.
        new: Option<String>,
    },
    /// Rewrite one exact property value.
    Value {
        /// Test class owning the property.
        class_name: String,
        /// Property name.
        property: String,
        /// Historical value.
        old: String,
        /// Current value.
        new: String,
    },
}

/// Result of applying class and GUI upgrades.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpgradedElement {
    /// The upgraded class name (or original when no rule matched).
    pub test_class: String,
    /// The upgraded GUI class name (or original when no rule matched).
    pub gui_class: String,
    /// Whether a class or GUI rule changed either value.
    pub changed: bool,
}

/// Versioned, data-only compatibility upgrade registry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpgradeRegistry {
    version: RegistryVersion,
    class_rules: BTreeMap<String, String>,
    class_and_gui_rules: BTreeMap<(String, String), String>,
    property_rules: BTreeMap<(String, String), Option<String>>,
    value_rules: BTreeMap<(String, String, String), String>,
    rules: Vec<UpgradeRule>,
    // See `AliasRegistry::load_error` for why this is retained rather than
    // replaced with an empty, apparently valid table.
    load_error: Option<RegistryError>,
}

fn detect_upgrade_cycle(graph: &BTreeMap<String, BTreeSet<String>>) -> Option<String> {
    // Use an explicit DFS stack so a caller-provided table cannot consume the
    // Rust call stack.  The registry parser rejects every possible class
    // transition cycle before an UpgradeRegistry becomes usable.
    let mut colors = BTreeMap::<String, u8>::new();
    for start in graph.keys() {
        if colors.get(start).copied() == Some(2) {
            continue;
        }
        let mut stack = vec![(start.clone(), false)];
        while let Some((node, leaving)) = stack.pop() {
            if leaving {
                colors.insert(node, 2);
                continue;
            }
            match colors.get(&node).copied() {
                Some(1) => return Some(node),
                Some(2) => continue,
                _ => {
                    colors.insert(node.clone(), 1);
                    stack.push((node.clone(), true));
                    if let Some(next_nodes) = graph.get(&node) {
                        for next in next_nodes.iter().rev() {
                            stack.push((next.clone(), false));
                        }
                    }
                }
            }
        }
    }
    None
}

impl UpgradeRegistry {
    /// Loads a registry for a profile identifier currently supported by this
    /// crate. Only `jmeter-5.6.3` is pinned in the initial profile.
    pub fn for_profile(profile_id: &str) -> std::result::Result<Self, RegistryError> {
        if profile_id == RegistryVersion::JMETER_5_6_3.profile_id() {
            Self::jmeter_5_6_3()
        } else {
            Err(RegistryError::UnsupportedProfile {
                profile_id: profile_id.to_owned(),
            })
        }
    }

    /// Loads the pinned JMeter 5.6.3 upgrade table.
    pub fn jmeter_5_6_3() -> std::result::Result<Self, RegistryError> {
        Self::from_properties(UPGRADE_5_6_3, RegistryVersion::JMETER_5_6_3)
    }

    /// Parses a caller-provided upgrade table without executing classes.
    pub fn from_properties(
        source: &str,
        version: RegistryVersion,
    ) -> std::result::Result<Self, RegistryError> {
        let mut registry = Self {
            version,
            class_rules: BTreeMap::new(),
            class_and_gui_rules: BTreeMap::new(),
            property_rules: BTreeMap::new(),
            value_rules: BTreeMap::new(),
            rules: Vec::new(),
            load_error: None,
        };
        for (line_index, raw_line) in source.lines().enumerate() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
                continue;
            }
            let Some((left, right)) = line.split_once('=') else {
                return Err(RegistryError::MalformedLine {
                    line: line_index + 1,
                });
            };
            let left = left.trim();
            let right = right.trim();
            if left.is_empty() {
                return Err(RegistryError::MalformedLine {
                    line: line_index + 1,
                });
            }
            if let Some((class_name, old_gui)) = left.split_once('|') {
                if class_name.trim().is_empty() || old_gui.trim().is_empty() || right.is_empty() {
                    return Err(RegistryError::MalformedLine {
                        line: line_index + 1,
                    });
                }
                let key = (class_name.trim().to_owned(), old_gui.trim().to_owned());
                if let Some(existing) = registry.class_and_gui_rules.get(&key)
                    && existing != right
                {
                    return Err(RegistryError::ConflictingUpgrade {
                        key: format!("{}|{}", key.0, key.1),
                    });
                }
                registry
                    .class_and_gui_rules
                    .insert(key.clone(), right.to_owned());
                registry.rules.push(UpgradeRule::ClassAndGui {
                    old_class: key.0,
                    old_gui: key.1,
                    new_class: right.to_owned(),
                });
                continue;
            }
            let Some((prefix, old_value)) = left.split_once('/') else {
                if right.is_empty() {
                    return Err(RegistryError::MalformedLine {
                        line: line_index + 1,
                    });
                }
                if let Some(existing) = registry.class_rules.get(left)
                    && existing != right
                {
                    return Err(RegistryError::ConflictingUpgrade {
                        key: left.to_owned(),
                    });
                }
                registry
                    .class_rules
                    .insert(left.to_owned(), right.to_owned());
                registry.rules.push(UpgradeRule::Class {
                    old: left.to_owned(),
                    new: right.to_owned(),
                });
                continue;
            };
            if prefix.is_empty() || old_value.is_empty() {
                return Err(RegistryError::MalformedLine {
                    line: line_index + 1,
                });
            }

            // Property rules use an exact class prefix. Value rules have the
            // property appended to the class with a dot; split at the last
            // dot, which is sufficient for the pinned table and remains data-
            // only for future profiles.
            let class_tail_is_uppercase = prefix
                .rsplit('.')
                .next()
                .and_then(|tail| tail.chars().next())
                .is_some_and(char::is_uppercase);
            if class_tail_is_uppercase {
                let new = (!right.is_empty()).then(|| right.to_owned());
                let key = (prefix.to_owned(), old_value.to_owned());
                if let Some(existing) = registry.property_rules.get(&key)
                    && existing != &new
                {
                    return Err(RegistryError::ConflictingUpgrade {
                        key: format!("{}/{}", key.0, key.1),
                    });
                }
                registry.property_rules.insert(key.clone(), new.clone());
                registry.rules.push(UpgradeRule::Property {
                    class_name: key.0,
                    old: key.1,
                    new,
                });
            } else if let Some(dot) = prefix.rfind('.') {
                let class_name = &prefix[..dot];
                let property = &prefix[dot + 1..];
                let key = (
                    class_name.to_owned(),
                    property.to_owned(),
                    old_value.to_owned(),
                );
                if let Some(existing) = registry.value_rules.get(&key)
                    && existing != right
                {
                    return Err(RegistryError::ConflictingUpgrade {
                        key: format!("{}.{} / {}", key.0, key.1, key.2),
                    });
                }
                registry.value_rules.insert(key.clone(), right.to_owned());
                registry.rules.push(UpgradeRule::Value {
                    class_name: key.0,
                    property: key.1,
                    old: key.2,
                    new: right.to_owned(),
                });
            } else {
                return Err(RegistryError::MalformedLine {
                    line: line_index + 1,
                });
            }
        }
        // Pair rules are also class transitions.  Validate the combined graph
        // before exposing the registry so upgrade_element can resolve an
        // arbitrarily long acyclic chain without a silent iteration cutoff.
        let mut class_graph = BTreeMap::<String, BTreeSet<String>>::new();
        for (old, new) in &registry.class_rules {
            class_graph
                .entry(old.clone())
                .or_default()
                .insert(new.clone());
        }
        for ((old_class, _old_gui), new_class) in &registry.class_and_gui_rules {
            class_graph
                .entry(old_class.clone())
                .or_default()
                .insert(new_class.clone());
        }
        if let Some(cycle) = detect_upgrade_cycle(&class_graph) {
            return Err(RegistryError::ConflictingUpgrade {
                key: format!("cyclic class mapping at {cycle}"),
            });
        }
        Ok(registry)
    }

    /// Validates that the embedded or caller-provided table loaded cleanly.
    pub fn validate(&self) -> std::result::Result<(), RegistryError> {
        self.load_error.clone().map_or(Ok(()), Err)
    }

    fn invalid(version: RegistryVersion, error: RegistryError) -> Self {
        Self {
            version,
            class_rules: BTreeMap::new(),
            class_and_gui_rules: BTreeMap::new(),
            property_rules: BTreeMap::new(),
            value_rules: BTreeMap::new(),
            rules: Vec::new(),
            load_error: Some(error),
        }
    }

    /// Returns provenance metadata for this table.
    #[must_use]
    pub const fn version(&self) -> RegistryVersion {
        self.version
    }

    /// Returns the parsed rules in source order.
    #[must_use]
    pub fn rules(&self) -> &[UpgradeRule] {
        &self.rules
    }

    /// Returns the number of active parsed upgrade rules.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Applies a class and GUI upgrade without loading any class.
    #[must_use]
    pub fn upgrade_element(&self, test_class: &str, gui_class: &str) -> UpgradedElement {
        let mut current_class = test_class.to_owned();
        let mut current_gui = gui_class.to_owned();
        let mut changed = false;
        loop {
            let mut progressed = false;

            // A pair rule is a test-class migration conditioned on the
            // historical GUI class. Apply it before the independent GUI
            // mapping below so the old GUI still participates in the match.
            if let Some(next) = self
                .class_and_gui_rules
                .get(&(current_class.clone(), current_gui.clone()))
                && next != &current_class
            {
                current_class = next.clone();
                changed = true;
                progressed = true;
            } else if let Some(next) = self.class_rules.get(&current_class)
                && next != &current_class
            {
                current_class = next.clone();
                changed = true;
                progressed = true;
            }

            // Plain class mappings include upstream GUI-only mappings. Apply
            // those independently so a GUI rename never changes test-class
            // identity.
            if let Some(next) = self.class_rules.get(&current_gui)
                && next != &current_gui
            {
                current_gui = next.clone();
                changed = true;
                progressed = true;
            }
            if !progressed {
                break;
            }
        }
        UpgradedElement {
            test_class: current_class,
            gui_class: current_gui,
            changed,
        }
    }

    /// Applies a property-name upgrade. `None` means the old property was
    /// explicitly deleted by the pinned table; `Some(name)` keeps a property.
    #[must_use]
    pub fn upgrade_property_name(&self, class_name: &str, property: &str) -> Option<String> {
        self.property_rules
            .get(&(class_name.to_owned(), property.to_owned()))
            .cloned()
            .unwrap_or_else(|| Some(property.to_owned()))
    }

    /// Applies an exact property-value upgrade.
    #[must_use]
    pub fn upgrade_property_value(&self, class_name: &str, property: &str, value: &str) -> String {
        self.value_rules
            .get(&(class_name.to_owned(), property.to_owned(), value.to_owned()))
            .cloned()
            .unwrap_or_else(|| value.to_owned())
    }
}

impl Default for UpgradeRegistry {
    fn default() -> Self {
        Self::jmeter_5_6_3()
            .unwrap_or_else(|error| Self::invalid(RegistryVersion::JMETER_5_6_3, error))
    }
}

/// The pinned pair of SaveService and upgrade registries.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct JmxRegistry {
    /// Alias table.
    pub aliases: AliasRegistry,
    /// Historical upgrade table.
    pub upgrades: UpgradeRegistry,
}

impl JmxRegistry {
    /// Loads both registries for a supported profile identifier.
    pub fn for_profile(profile_id: &str) -> std::result::Result<Self, RegistryError> {
        if profile_id == RegistryVersion::JMETER_5_6_3.profile_id() {
            Self::jmeter_5_6_3()
        } else {
            Err(RegistryError::UnsupportedProfile {
                profile_id: profile_id.to_owned(),
            })
        }
    }

    /// Loads the pinned JMeter 5.6.3 registries.
    pub fn jmeter_5_6_3() -> std::result::Result<Self, RegistryError> {
        Ok(Self {
            aliases: AliasRegistry::jmeter_5_6_3()?,
            upgrades: UpgradeRegistry::jmeter_5_6_3()?,
        })
    }

    /// Loads the pinned pair and returns any embedded-table parse failure.
    pub fn try_default() -> std::result::Result<Self, RegistryError> {
        Self::jmeter_5_6_3()
    }

    /// Validates both embedded or caller-provided tables.
    pub fn validate(&self) -> std::result::Result<(), RegistryError> {
        self.aliases.validate()?;
        self.upgrades.validate()
    }

    /// Returns pinned provenance metadata.
    #[must_use]
    pub const fn version(&self) -> RegistryVersion {
        self.aliases.version()
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn sha256(input: &[u8]) -> [u8; 32] {
        const K: [u32; 64] = [
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
        let mut state: [u32; 8] = [
            0x6a09_e667,
            0xbb67_ae85,
            0x3c6e_f372,
            0xa54f_f53a,
            0x510e_527f,
            0x9b05_688c,
            0x1f83_d9ab,
            0x5be0_cd19,
        ];
        let bit_len = (input.len() as u64).saturating_mul(8);
        let padded_len = (input.len() + 9).div_ceil(64) * 64;
        let mut padded = vec![0_u8; padded_len];
        padded[..input.len()].copy_from_slice(input);
        padded[input.len()] = 0x80;
        padded[padded_len - 8..].copy_from_slice(&bit_len.to_be_bytes());
        for chunk in padded.chunks_exact(64) {
            let mut words = [0_u32; 64];
            for (index, bytes) in chunk.chunks_exact(4).take(16).enumerate() {
                words[index] = u32::from_be_bytes(bytes.try_into().expect("word"));
            }
            for index in 16..64 {
                let s0 = words[index - 15].rotate_right(7)
                    ^ words[index - 15].rotate_right(18)
                    ^ (words[index - 15] >> 3);
                let s1 = words[index - 2].rotate_right(17)
                    ^ words[index - 2].rotate_right(19)
                    ^ (words[index - 2] >> 10);
                words[index] = words[index - 16]
                    .wrapping_add(s0)
                    .wrapping_add(words[index - 7])
                    .wrapping_add(s1);
            }
            let mut working = state;
            for index in 0..64 {
                let s1 = working[4].rotate_right(6)
                    ^ working[4].rotate_right(11)
                    ^ working[4].rotate_right(25);
                let choice = (working[4] & working[5]) ^ ((!working[4]) & working[6]);
                let temp1 = working[7]
                    .wrapping_add(s1)
                    .wrapping_add(choice)
                    .wrapping_add(K[index])
                    .wrapping_add(words[index]);
                let s0 = working[0].rotate_right(2)
                    ^ working[0].rotate_right(13)
                    ^ working[0].rotate_right(22);
                let majority = (working[0] & working[1])
                    ^ (working[0] & working[2])
                    ^ (working[1] & working[2]);
                let temp2 = s0.wrapping_add(majority);
                working[7] = working[6];
                working[6] = working[5];
                working[5] = working[4];
                working[4] = working[3].wrapping_add(temp1);
                working[3] = working[2];
                working[2] = working[1];
                working[1] = working[0];
                working[0] = temp1.wrapping_add(temp2);
            }
            for index in 0..8 {
                state[index] = state[index].wrapping_add(working[index]);
            }
        }
        let mut digest = [0_u8; 32];
        for (index, word) in state.into_iter().enumerate() {
            digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        digest
    }

    fn hex(bytes: [u8; 32]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn pinned_alias_table_contains_structural_and_fixture_aliases() {
        let registry = AliasRegistry::jmeter_5_6_3().expect("embedded table is valid");
        assert_eq!(registry.version(), RegistryVersion::JMETER_5_6_3);
        assert_eq!(
            registry.alias_count(),
            RegistryVersion::JMETER_5_6_3_ALIAS_COUNT
        );
        assert_eq!(
            registry.primary_alias_count(),
            RegistryVersion::JMETER_5_6_3_PRIMARY_ALIAS_COUNT
        );
        assert_eq!(
            hex(sha256(SAVESERVICE_5_6_3.as_bytes())),
            RegistryVersion::JMETER_5_6_3_SAVESERVICE_SHA256
        );
        assert_eq!(
            registry.class_for_alias("jmeterTestPlan"),
            Some("org.apache.jmeter.save.ScriptWrapper")
        );
        assert_eq!(
            registry.class_for_alias("hashTree"),
            Some("org.apache.jorphan.collections.ListedHashTree")
        );
        assert_eq!(
            registry.class_for_alias("TestPlan"),
            Some("org.apache.jmeter.testelement.TestPlan")
        );
        assert_eq!(
            registry.class_for_alias("DebugSampler"),
            Some("org.apache.jmeter.sampler.DebugSampler")
        );
        assert_eq!(
            registry.primary_alias_for_class(
                "org.apache.jmeter.protocol.http.sampler.HTTPSamplerProxy"
            ),
            Some("HTTPSamplerProxy")
        );
        assert_eq!(
            registry.canonical_alias(
                "HTTPSampler2",
                "org.apache.jmeter.protocol.http.sampler.HTTPSamplerProxy"
            ),
            "HTTPSamplerProxy"
        );
    }

    #[test]
    fn pinned_upgrade_table_is_data_only_and_versioned() {
        let registry = UpgradeRegistry::jmeter_5_6_3().expect("embedded table is valid");
        assert_eq!(registry.version().jmeter_version, "5.6.3");
        assert_eq!(
            registry.rule_count(),
            RegistryVersion::JMETER_5_6_3_UPGRADE_RULE_COUNT
        );
        assert_eq!(
            hex(sha256(UPGRADE_5_6_3.as_bytes())),
            RegistryVersion::JMETER_5_6_3_UPGRADE_SHA256
        );
        let upgraded = registry.upgrade_element(
            "org.apache.jmeter.protocol.http.sampler.HTTPSamplerFull",
            "HttpTestSampleGui",
        );
        assert_eq!(
            upgraded.test_class,
            "org.apache.jmeter.protocol.http.sampler.HTTPSampler"
        );
        assert_eq!(
            registry.upgrade_property_name(
                "org.apache.jmeter.protocol.jdbc.sampler.JDBCSampler",
                "JDBCSampler.query",
            ),
            Some("query".to_owned())
        );

        let paired = registry.upgrade_element(
            "org.apache.jmeter.config.ConfigTestElement",
            "org.apache.jmeter.protocol.jdbc.config.gui.DbConfigGui",
        );
        assert_eq!(
            paired.test_class,
            "org.apache.jmeter.protocol.jdbc.config.DataSourceElement"
        );
        assert_eq!(
            paired.gui_class,
            "org.apache.jmeter.testbeans.gui.TestBeanGUI"
        );
        let class_without_pair = registry.upgrade_element(
            "org.apache.jmeter.config.ConfigTestElement",
            "org.example.UnrelatedGui",
        );
        assert_eq!(
            class_without_pair.test_class,
            "org.apache.jmeter.config.ConfigTestElement"
        );
    }

    #[test]
    fn upgrade_element_resolves_chains_longer_than_legacy_cutoff() {
        let source = (0..17)
            .map(|index| format!("C{index}=C{}\n", index + 1))
            .collect::<String>();
        let registry = UpgradeRegistry::from_properties(&source, RegistryVersion::JMETER_5_6_3)
            .expect("long acyclic chain is valid");
        let upgraded = registry.upgrade_element("C0", "Gui");
        assert_eq!(upgraded.test_class, "C17");
        assert!(upgraded.changed);
    }

    #[test]
    fn every_pinned_alias_has_a_stable_resolution_and_primary_alias() {
        let registry = AliasRegistry::jmeter_5_6_3().expect("embedded table is valid");
        let mut count = 0;
        for (alias, class_name) in registry.aliases() {
            let resolution = registry.resolve(alias);
            assert_eq!(resolution.class_name.as_deref(), Some(class_name));
            assert_eq!(
                resolution.primary_alias.as_deref(),
                registry.primary_alias_for_class(class_name)
            );
            count += 1;
        }
        assert!(
            count >= 250,
            "pinned SaveService vocabulary unexpectedly shrank"
        );
    }

    #[test]
    fn registry_rejects_malformed_and_conflicting_entries() {
        let version = RegistryVersion::JMETER_5_6_3;
        assert_eq!(
            AliasRegistry::from_properties("Alias=\n", version)
                .expect_err("empty alias target must fail")
                .code(),
            "jmx.registry.malformed-line"
        );
        assert_eq!(
            AliasRegistry::from_properties("A=Class\nB=Class\n", version)
                .expect_err("one class cannot have two primaries")
                .code(),
            "jmx.registry.conflicting-primary"
        );
        assert_eq!(
            UpgradeRegistry::from_properties("Old=New\nOld=Other\n", version)
                .expect_err("one class cannot have two upgrade targets")
                .code(),
            "jmx.registry.conflicting-upgrade"
        );
        assert_eq!(
            UpgradeRegistry::from_properties("Old=Old\n", version)
                .expect_err("class upgrade cycles must fail")
                .code(),
            "jmx.registry.conflicting-upgrade"
        );
    }

    #[test]
    fn registry_errors_do_not_echo_user_controlled_identifiers() {
        let secret = "secret-registry-identifier";
        let error = AliasRegistry::from_properties(
            &format!("{secret}=First\n{secret}=Second\n"),
            RegistryVersion::JMETER_5_6_3,
        )
        .expect_err("conflicting alias");
        assert!(!error.to_string().contains(secret));
        assert!(!format!("{error:?}").contains(secret));
        let error = UpgradeRegistry::for_profile(secret).expect_err("unsupported profile");
        assert!(!error.to_string().contains(secret));
        assert!(!format!("{error:?}").contains(secret));
    }

    #[test]
    fn every_pinned_upgrade_rule_is_applied_as_data() {
        let registry = UpgradeRegistry::jmeter_5_6_3().expect("embedded table is valid");
        assert!(!registry.rules().is_empty());
        for rule in registry.rules() {
            match rule {
                UpgradeRule::Class { old, new } => {
                    assert_eq!(registry.upgrade_element(old, "Gui").test_class, *new);
                }
                UpgradeRule::ClassAndGui {
                    old_class,
                    old_gui,
                    new_class,
                } => {
                    assert_eq!(
                        registry.upgrade_element(old_class, old_gui).test_class,
                        *new_class
                    );
                }
                UpgradeRule::Property {
                    class_name,
                    old,
                    new,
                } => {
                    assert_eq!(registry.upgrade_property_name(class_name, old), *new);
                }
                UpgradeRule::Value {
                    class_name,
                    property,
                    old,
                    new,
                } => {
                    assert_eq!(
                        registry.upgrade_property_value(class_name, property, old),
                        *new
                    );
                }
            }
        }
    }

    #[test]
    fn default_registry_exposes_typed_embedded_load_status() {
        let loaded = JmxRegistry::try_default().expect("pinned registries are valid");
        loaded.validate().expect("loaded registries validate");
        JmxRegistry::default()
            .validate()
            .expect("default registries validate");
    }
}
