#![no_main]

//! Bounded JMX syntax and semantic round-trip target.
//!
//! The target deliberately does not load classes, resolve entities, read
//! files, or execute a plan.  Successful semantic inputs are re-encoded and
//! parsed again so a minimized corpus case can expose a no-drop regression.
//!
//! Invariants: `JMX-LIMIT-001` rejects oversized source bytes without
//! truncation; `JMX-SOURCE-RETAIN-001` checks syntax-source retention;
//! `JMX-OPAQUE-INVENTORY-001` checks unknown element and extension bytes; and
//! `JMX-DROPPED-INVENTORY-001` checks the typed inventory for upgrade
//! properties on decoded known elements that canonicalization intentionally
//! removes.  Fixed probes cover standard object properties, an upgrade alias,
//! comments/processing instructions at every wrapper level, and opaque plugin
//! subtrees.
//! Source-side coverage: raw syntax bytes, opaque subtree bytes, and the
//! explicitly dropped-property inventory are compared without decoding them
//! into expected values first.
//! I/O policy: none; parsing and bounded output use in-memory buffers only.

use std::io::{self, Write};

use jmeter_rs_jmx::{
    DecodeLimits, DecodeOptions, Error, LimitKind, Limits, Parser, SemanticDocument,
};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 256 * 1024;
const MAX_OUTPUT_BYTES: usize = 512 * 1024;

fn syntax_limits() -> Limits {
    Limits {
        max_bytes: MAX_INPUT_BYTES,
        ..Limits::small()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DroppedProperty {
    node_id: u64,
    source_bytes: usize,
}

fn dropped_property_inventory(document: &SemanticDocument) -> Vec<DroppedProperty> {
    let dropped_diagnostics: Vec<_> = document
        .diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.code == "jmx.semantic.upgraded_property_dropped")
        .collect();
    for diagnostic in &dropped_diagnostics {
        if diagnostic.node_id.is_none() {
            panic!("dropped-property diagnostic lost its node identity");
        }
    }

    let source_inventory = document.dropped_property_inventory();
    if dropped_diagnostics.len() != source_inventory.len() {
        panic!(
            "dropped-property diagnostic and source inventories disagree: {} != {}",
            dropped_diagnostics.len(),
            source_inventory.len()
        );
    }

    let mut inventory = Vec::new();
    for dropped in source_inventory {
        let node_id = dropped.node_id;
        // A known element has a typed semantic property inventory.  An opaque
        // element can still contain a matching XML name, but that name belongs
        // to the retained raw subtree rather than to the canonical semantic
        // projection.  Do not classify it as a re-emission by looking at bytes.
        if document.is_opaque(node_id) {
            continue;
        }
        if document.tree().element(node_id).is_err() {
            panic!("dropped-property diagnostic points at a missing element");
        }
        inventory.push(DroppedProperty {
            node_id: node_id.as_u64(),
            source_bytes: dropped.source_bytes,
        });
    }
    inventory
}

fn opaque_element_inventory(document: &SemanticDocument) -> Vec<(u64, Vec<u8>)> {
    document
        .node_ids()
        .into_iter()
        .filter_map(|id| {
            document
                .opaque_element_bytes(id)
                .map(|bytes| (id.as_u64(), bytes.to_vec()))
        })
        .collect()
}

fn extension_inventory(document: &SemanticDocument) -> Vec<(String, Vec<u8>)> {
    let mut inventory = Vec::new();
    inventory.extend(
        document
            .leading_extensions()
            .iter()
            .map(|extension| (extension.type_name.clone(), extension.raw.clone())),
    );
    inventory.extend(
        document
            .root_extensions()
            .iter()
            .map(|extension| (extension.type_name.clone(), extension.raw.clone())),
    );
    inventory.extend(
        document
            .root_hash_tree_extensions()
            .iter()
            .map(|extension| (extension.type_name.clone(), extension.raw.clone())),
    );
    for id in document.node_ids() {
        if let Some(extensions) = document.hash_tree_extensions(id) {
            inventory.extend(
                extensions
                    .iter()
                    .map(|extension| (extension.type_name.clone(), extension.raw.clone())),
            );
        }
        let Ok(element) = document.tree().element(id) else {
            panic!("extension inventory points at a missing element");
        };
        inventory.extend(
            element
                .opaque_extensions
                .iter()
                .map(|extension| (extension.type_name.clone(), extension.raw.clone())),
        );
    }
    inventory.extend(
        document
            .trailing_extensions()
            .iter()
            .map(|extension| (extension.type_name.clone(), extension.raw.clone())),
    );
    inventory
}

fn assert_bounded_inventories(
    extensions: &[(String, Vec<u8>)],
    opaque_elements: &[(u64, Vec<u8>)],
) {
    let entry_count = extensions
        .len()
        .checked_add(opaque_elements.len())
        .expect("opaque inventory count overflowed");
    let maximum_entries = Limits::small().max_nodes;
    if entry_count > maximum_entries {
        panic!("opaque inventory exceeded bounded entry count: {entry_count}");
    }

    let mut retained_bytes = 0usize;
    for (_, raw) in extensions {
        retained_bytes = retained_bytes
            .checked_add(raw.len())
            .expect("opaque inventory byte count overflowed");
    }
    for (_, raw) in opaque_elements {
        retained_bytes = retained_bytes
            .checked_add(raw.len())
            .expect("opaque inventory byte count overflowed");
    }
    let maximum_bytes = DecodeLimits::small().max_opaque_bytes;
    if retained_bytes > maximum_bytes {
        panic!("opaque inventory exceeded bounded byte count: {retained_bytes}");
    }
}

fn assert_semantic_round_trip(semantic: &SemanticDocument) {
    let opaque_inventory = opaque_element_inventory(semantic);
    let source_extension_inventory = extension_inventory(semantic);
    assert_bounded_inventories(&source_extension_inventory, &opaque_inventory);
    let dropped_inventory = dropped_property_inventory(semantic);

    let mut output = BoundedOutput::new(MAX_OUTPUT_BYTES);
    if semantic.write_canonical(&mut output).is_err() {
        panic!("fixed JMX semantic probe could not be encoded");
    }
    let encoded = output.finish();
    let Ok(reparsed) = SemanticDocument::from_bytes(&encoded) else {
        panic!("canonical JMX output was not parseable");
    };

    if opaque_inventory != opaque_element_inventory(&reparsed) {
        panic!("canonical JMX output changed opaque element bytes");
    }
    if source_extension_inventory != extension_inventory(&reparsed) {
        panic!("canonical JMX output changed retained XML extension bytes");
    }
    let reparsed_opaque_inventory = opaque_element_inventory(&reparsed);
    let reparsed_extension_inventory = extension_inventory(&reparsed);
    assert_bounded_inventories(&reparsed_extension_inventory, &reparsed_opaque_inventory);

    let reparsed_dropped_inventory = dropped_property_inventory(&reparsed);
    if !reparsed_dropped_inventory.is_empty() {
        panic!(
            "canonical JMX output invented known deleted properties: {reparsed_dropped_inventory:?}"
        );
    }
    // Keep the source inventory live in the invariant even when the input has
    // no deleted known properties.  The raw source length is diagnostic data,
    // not a byte pattern to search for in canonical output (which may contain
    // the same bytes inside an opaque subtree).
    let reparsed_ids = reparsed.node_ids();
    for dropped in &dropped_inventory {
        if dropped.source_bytes == 0 {
            panic!("known deleted property has no retained source bytes");
        }
        let Some(reparsed_id) = reparsed_ids
            .iter()
            .copied()
            .find(|id| id.as_u64() == dropped.node_id)
        else {
            panic!("canonical JMX output dropped the known element carrying a deleted property");
        };
        if reparsed.tree().element(reparsed_id).is_err() {
            panic!("canonical JMX output dropped the known element carrying a deleted property");
        }
    }
    if semantic != &reparsed {
        panic!("canonical JMX output dropped semantic data");
    }
}

fn fixed_semantic_probes() {
    // These are original, bounded in-memory probes rather than upstream
    // fixtures.  They exercise the public JMX API at the same boundary as the
    // fuzzed input; corpus provenance remains in fuzz/corpus/PROVENANCE.md.
    let probes: &[(&str, &[u8])] = &[
        (
            "standard-child-name-objprop",
            &br#"<jmeterTestPlan version="1.2" properties="5.0" jmeter="5.6.3"><hashTree><TestPlan guiclass="TestPlanGui" testclass="TestPlan" testname="objprop" enabled="true"><objProp><name>standard.object</name><value class="fixture.Type" encoding="utf-8">opaque &amp; bytes</value></objProp></TestPlan><hashTree/></hashTree></jmeterTestPlan>"#[..],
        ),
        (
            "upgrade-alias",
            &br#"<jmeterTestPlan version="1.2"><hashTree><JDBCDataSource guiclass="TestBeanGUI" testclass="org.apache.jmeter.protocol.jdbc.config.DataSourceElement" testname="alias" enabled="true"><stringProp name="JDBCSampler.connections">deleted</stringProp><stringProp name="JDBCSampler.maxuse">3</stringProp></JDBCDataSource><hashTree/></hashTree></jmeterTestPlan>"#[..],
        ),
        (
            "comments-processing-instructions",
            &br#"<?xml version="1.0"?><jmeterTestPlan version="1.2"><!--root-before--><?root-pi yes?><hashTree><!--tree-before--><?tree-pi yes?><TestPlan guiclass="TestPlanGui" testclass="TestPlan" testname="extensions" enabled="true"><!--element-before--><?element-pi yes?><stringProp name="value">text</stringProp><!--element-after--><?element-pi-after yes?></TestPlan><hashTree/><!--tree-after--><?tree-pi-after yes?></hashTree></jmeterTestPlan>"#[..],
        ),
        (
            "top-level-comments-and-opaque",
            &br#"<!--before--><?before yes?><jmeterTestPlan version="1.2"><hashTree><TestPlan guiclass="TestPlanGui" testclass="TestPlan" testname="known" enabled="true"><extensionNode/><mysteryProp name="opaque.value">raw &amp; value</mysteryProp></TestPlan><hashTree/><MysteryPlugin guiclass="MysteryGui" testclass="com.example.Mystery" testname="unknown" enabled="true"><mysteryProp name="plugin.value">plugin &amp; bytes</mysteryProp></MysteryPlugin><hashTree/></hashTree></jmeterTestPlan><!--after--><?after yes?>"#[..],
        ),
    ];

    for (name, source) in probes {
        let semantic = SemanticDocument::from_bytes(source)
            .unwrap_or_else(|error| panic!("fixed JMX probe {name} did not decode: {error}"));
        if *name == "top-level-comments-and-opaque" {
            assert_eq!(semantic.leading_extensions().len(), 2);
            assert_eq!(semantic.trailing_extensions().len(), 2);
            let extensions = extension_inventory(&semantic);
            assert_eq!(extensions.len(), 5);
            assert_eq!(
                extensions
                    .iter()
                    .filter(|(type_name, _)| type_name == "xml:extensionNode")
                    .count(),
                1
            );
            let opaque_elements = opaque_element_inventory(&semantic);
            assert_eq!(opaque_elements.len(), 1);
            assert!(!opaque_elements[0].1.is_empty());
            assert_bounded_inventories(&extensions, &opaque_elements);
        }
        assert_semantic_round_trip(&semantic);
    }
}

/// A writer which checks the output budget before accepting each encoder
/// write.  Keeping the bound at the writer boundary prevents the semantic
/// encoder from growing an unbounded output `Vec` and only checking its size
/// after serialization has already completed.
struct BoundedOutput {
    bytes: Vec<u8>,
    maximum: usize,
}

impl BoundedOutput {
    fn new(maximum: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(maximum),
            maximum,
        }
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

impl Write for BoundedOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next =
            self.bytes.len().checked_add(bytes.len()).ok_or_else(|| {
                io::Error::new(io::ErrorKind::WriteZero, "output length overflow")
            })?;
        if next > self.maximum {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "JMX output byte budget exceeded",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fuzz_target!(|data: &[u8]| {
    fixed_semantic_probes();

    let limits = syntax_limits();
    if data.len() > MAX_INPUT_BYTES {
        match Parser::with_limits(limits).parse(data) {
            Err(Error::LimitExceeded {
                kind: LimitKind::Bytes,
                ..
            }) => {}
            Err(error) => panic!("oversized JMX input returned the wrong error: {error}"),
            Ok(_) => panic!("oversized JMX input was accepted instead of rejected"),
        }
        return;
    }

    let Ok(document) = Parser::with_limits(limits).parse(data) else {
        return;
    };

    // The syntax layer is source-preserving for every accepted input.
    let retained = document.to_bytes();
    if retained.as_slice() != data {
        panic!("accepted JMX input was not retained byte-for-byte");
    }

    let options = DecodeOptions {
        limits: DecodeLimits::small(),
        ..DecodeOptions::default()
    };
    let Ok(semantic) = SemanticDocument::decode_with_options(&document, options) else {
        return;
    };
    // Reuse the same typed inventories as the fixed probes.  In particular,
    // never scan canonical bytes for a dropped property's raw bytes: an
    // opaque extension is allowed to contain that byte sequence verbatim.
    assert_semantic_round_trip(&semantic);
});
