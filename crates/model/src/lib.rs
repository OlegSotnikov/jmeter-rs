// SPDX-License-Identifier: Apache-2.0
//! Runtime-independent semantic data types for Apache JMeter plans.
//!
//! The model deliberately keeps the two kinds of ordering that are observable
//! in a JMX document: properties retain insertion order and tree children
//! retain insertion order.  Tree identity is represented by [`NodeId`], never
//! by an element name or by value equality.  This lets a plan contain two
//! elements that look identical while still addressing either one safely.
//!
//! This crate has no parser, serializer, filesystem, network, or executor
//! dependency.  Those concerns belong to the JMX and runtime boundaries.
//!
//! In particular, this crate does not duplicate raw XML.  Exact tags,
//! lexical attributes, source placement, comments, and unknown subtree event
//! order are retained by `crates/jmx` sidecars.  A model-only conversion that
//! promises to reproduce that wire stream must return
//! [`ModelCapabilityError::UnsupportedLosslessWire`] instead of silently
//! dropping those fields.

mod element;
mod error;
mod id;
mod limits;
mod opaque;
mod property;
mod source;
mod tree;

pub use element::{ElementMetadata, TestElement};
pub use error::{
    MetadataField, ModelCapabilityError, ModelError, ModelValidationError, PropertyError,
    PropertyTypeError, TreeError,
};
pub use id::NodeId;
pub use limits::{ValidationLimitKind, ValidationLimits};
pub use opaque::{OpaqueData, OpaqueExtension, OpaqueValue, UnknownValue};
pub use property::{
    ElementProperty, JMeterProperties, MapEntry, ObjectPayloadKind, ObjectProperty,
    ObjectPropertyAttribute, OrderedProperties, Properties, PropertyEntry, PropertyKind,
    PropertyMap, PropertyValue,
};
pub use source::{SourceLocation, SourceLocationError};
pub use tree::{
    ElementTree, HashTree, IdentityTree, ListedHashTree, Node, PreorderIter, TraversalControl,
    TraversalOutcome, Tree, TreeNode, VisitEvent,
};

/// The element type used by a semantic JMeter plan tree.
pub type SemanticElement = TestElement;

/// Alias for callers that use visit terminology instead of traversal.
pub type VisitControl = TraversalControl;

/// Alias for callers that use tree-visit terminology.
pub type TreeVisit = VisitEvent;

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "deterministic unit tests assert successful setup before inspecting values"
)]
mod tests {
    use super::*;

    fn element(name: &str) -> TestElement {
        TestElement::named("example.TestElement", "example.Gui", name)
    }

    #[test]
    fn node_ids_are_document_local_and_metadata_is_exact() {
        let first = NodeId::new(41);
        let second = NodeId::new(41);
        assert_eq!(first, second);
        assert_eq!(first.get(), 41);
        assert_eq!(first.as_u64(), 41);
        assert!(!first.is_zero());
        assert_eq!(first.to_string(), "41");

        let metadata = ElementMetadata::new(
            "plug-in.TestElement<raw>",
            "plug-in.GuiElement",
            "  exact ☃ name  ",
        );
        assert_eq!(metadata.test_class, "plug-in.TestElement<raw>");
        assert_eq!(metadata.gui_class, "plug-in.GuiElement");
        assert_eq!(metadata.name, "  exact ☃ name  ");
        assert_eq!(metadata.testclass(), "plug-in.TestElement<raw>");
        assert_eq!(metadata.guiclass(), "plug-in.GuiElement");
        assert_eq!(metadata.testname(), "  exact ☃ name  ");

        let mut item = TestElement::new(metadata);
        assert!(item.is_enabled());
        item.set_enabled(false);
        assert!(!item.is_enabled());
        let location = SourceLocation::new(7, 3)
            .expect("positive source coordinates")
            .with_source("plan.jmx")
            .with_byte_offset(128);
        item.set_source_location(location.clone());
        assert_eq!(item.source(), &location);
        item.push_opaque_extension(OpaqueValue::text("plugin.Unknown", "raw-data"));
        assert_eq!(item.opaque_extensions.len(), 1);
        assert_eq!(
            item.opaque_extensions[0].as_text(),
            Some("raw-data"),
            "opaque bytes should remain inspectable without decoding"
        );
    }

    #[test]
    fn explicit_node_ids_preserve_roots_reject_collisions_and_bound_allocator() {
        let mut tree = IdentityTree::<u32>::new();
        let zero = tree
            .insert_with_id(None, NodeId::new(0), 0)
            .expect("zero is valid for imported IDs");
        let root = tree
            .insert_with_id(None, NodeId::new(10), 10)
            .expect("explicit root ID should be accepted");
        let child = tree
            .insert_with_id(Some(root), NodeId::new(20), 20)
            .expect("explicit child ID should be accepted");

        assert_eq!(zero, NodeId::new(0));
        assert_eq!(tree.root_ids(), &[zero, root]);
        assert_eq!(tree.children(root).unwrap(), &[child]);
        assert_eq!(
            tree.insert_with_id(None, NodeId::new(10), 999),
            Err(TreeError::DuplicateNodeId { id: root })
        );

        let automatic = tree
            .insert_root(21)
            .expect("allocator should advance beyond imported IDs");
        assert_eq!(automatic, NodeId::new(21));
        assert_eq!(tree.get_array(), vec![zero, root, automatic]);

        let maximum = tree
            .insert_with_id(None, NodeId::new(u64::MAX), u32::MAX)
            .expect("maximum imported ID should be representable");
        assert_eq!(maximum, NodeId::new(u64::MAX));
        assert_eq!(
            tree.insert_root(22),
            Err(TreeError::NodeIdExhausted),
            "automatic allocation must fail after the maximum ID"
        );
        assert!(tree.validate().is_ok());
    }

    #[test]
    fn property_order_replacement_and_absent_empty_null_are_distinct() {
        let mut properties = Properties::new();
        assert!(
            properties
                .insert("second", PropertyValue::Long(2))
                .is_none()
        );
        assert!(
            properties
                .insert("first", PropertyValue::String(String::new()))
                .is_none()
        );
        assert!(properties.insert("null", PropertyValue::Null).is_none());
        assert!(
            properties
                .insert("unknown", PropertyValue::opaque_text("plugin.Value", "x"))
                .is_none()
        );
        assert_eq!(
            properties.keys().collect::<Vec<_>>(),
            vec!["second", "first", "null", "unknown"]
        );
        assert!(!properties.contains("absent"));
        assert!(properties.get("absent").is_none());
        assert_eq!(
            properties.get("first"),
            Some(&PropertyValue::String(String::new()))
        );
        assert_eq!(properties.get("null"), Some(&PropertyValue::Null));

        let previous = properties.insert("first", PropertyValue::Boolean(true));
        assert_eq!(previous, Some(PropertyValue::String(String::new())));
        assert_eq!(properties.position("first"), Some(1));
        assert_eq!(
            properties.keys().collect::<Vec<_>>(),
            vec!["second", "first", "null", "unknown"]
        );
        assert_eq!(properties.get("first"), Some(&PropertyValue::Boolean(true)));

        let duplicate = properties.try_insert("first", PropertyValue::Integer(1));
        assert!(matches!(
            duplicate.as_ref(),
            Err(PropertyError::DuplicateName { name }) if name == "first"
        ));
        assert_eq!(
            duplicate.err().map(|error| error.code()),
            Some("model.property.duplicate-name")
        );
        let missing = properties.try_remove("absent");
        assert!(matches!(
            missing,
            Err(PropertyError::NameNotFound { name }) if name == "absent"
        ));

        let wrong_kind = PropertyValue::String("value".to_owned()).as_boolean();
        assert!(matches!(
            wrong_kind,
            Err(PropertyTypeError {
                expected: PropertyKind::Boolean,
                actual: PropertyKind::String
            })
        ));
        let unknown = properties.get("unknown").map(PropertyValue::as_opaque);
        assert_eq!(
            unknown.and_then(Result::ok).and_then(OpaqueValue::as_text),
            Some("x")
        );
    }

    #[test]
    fn property_name_edits_are_transactional_and_values_remain_mutable() {
        let mut properties = Properties::from_entries([
            PropertyEntry::new("first", PropertyValue::integer(1)),
            PropertyEntry::new("second", PropertyValue::integer(2)),
        ])
        .unwrap();
        let original = properties.clone();
        let duplicate = properties.edit(|entries| entries[1].name = "first".to_owned());
        assert_eq!(
            duplicate,
            Err(PropertyError::DuplicateName {
                name: "first".to_owned()
            })
        );
        assert_eq!(properties, original);

        for value in properties.values_mut() {
            if let PropertyValue::Integer(number) = value {
                *number += 10;
            }
        }
        assert_eq!(properties.get("first"), Some(&PropertyValue::Integer(11)));
        assert_eq!(properties.get("second"), Some(&PropertyValue::Integer(12)));
    }

    #[test]
    fn semantic_equality_excludes_runtime_diagnostics_and_normalizes_nan() {
        let mut left = element("semantic");
        left.set_property("value", PropertyValue::double(f64::NAN));
        let mut right = left.clone();
        right.set_source_location(SourceLocation::new(8, 4).expect("positive source coordinates"));
        right.set_temporary_property("runtime", PropertyValue::string("diagnostic"));
        right.set_running_version();

        assert!(left.semantic_eq(&right));
        assert!(!left.structural_eq(&right));

        let mut left_tree = ElementTree::new();
        let mut right_tree = ElementTree::new();
        left_tree.insert_root(left).unwrap();
        right_tree.insert_root(right).unwrap();
        assert!(left_tree.semantic_eq(&right_tree));
        assert!(!left_tree.structural_eq(&right_tree));
    }

    #[test]
    fn source_coordinates_and_direct_model_limits_are_validated() {
        assert_eq!(
            SourceLocation::try_new(0, 1),
            Err(SourceLocationError::InvalidLine { value: 0 })
        );
        assert_eq!(
            SourceLocation::try_new(1, 0),
            Err(SourceLocationError::InvalidColumn { value: 0 })
        );
        assert_eq!(
            SourceLocation::new(0, 1),
            Err(SourceLocationError::InvalidLine { value: 0 })
        );
        assert_eq!(
            SourceLocation::new(1, 0),
            Err(SourceLocationError::InvalidColumn { value: 0 })
        );
        assert!(SourceLocation::try_new(1, 1).is_ok());

        let invalid = TestElement::default();
        let error = invalid
            .validate_with_limits(&ValidationLimits::small())
            .unwrap_err();
        assert_eq!(error.code(), "model.validation.empty-metadata");

        let mut tree = ElementTree::new();
        tree.insert_root(element("one")).unwrap();
        tree.insert_root(element("two")).unwrap();
        let mut limits = ValidationLimits::small();
        limits.max_nodes = 1;
        let error = tree.validate_with_limits(&limits).unwrap_err();
        assert_eq!(error.code(), "model.validation.limit-nodes");

        let mut opaque_element = element("opaque");
        opaque_element.push_opaque_extension(OpaqueValue::new("plugin.Type", vec![1, 2, 3]));
        let mut limits = ValidationLimits::small();
        limits.max_opaque_bytes = 2;
        assert_eq!(
            opaque_element
                .validate_with_limits(&limits)
                .unwrap_err()
                .code(),
            "model.validation.limit-opaque-bytes"
        );

        let mut property_limited = element("property-limit");
        property_limited.set_property("value", PropertyValue::string("text"));
        let mut limits = ValidationLimits::small();
        limits.max_properties = 0;
        assert_eq!(
            property_limited
                .validate_with_limits(&limits)
                .unwrap_err()
                .code(),
            "model.validation.limit-properties"
        );

        let mut nested = ElementProperty::new("nested").with_class_name("plugin.Nested");
        nested
            .properties
            .insert("child", PropertyValue::string("value"));
        let mut depth_limited = element("depth-limit");
        depth_limited.set_property("nested", PropertyValue::Element(nested));
        let mut limits = ValidationLimits::small();
        limits.max_property_depth = 0;
        assert_eq!(
            depth_limited
                .validate_with_limits(&limits)
                .unwrap_err()
                .code(),
            "model.validation.limit-property-depth"
        );

        let mut string_limited = element("string-limit");
        string_limited.set_property("value", PropertyValue::string("long value"));
        let mut limits = ValidationLimits::small();
        limits.max_string_bytes = 1;
        assert_eq!(
            string_limited
                .validate_with_limits(&limits)
                .unwrap_err()
                .code(),
            "model.validation.limit-string-bytes"
        );
    }

    #[test]
    fn tree_depth_limits_have_exact_zero_based_boundaries() {
        let mut tree = ElementTree::new();
        let root = tree.insert_root(element("root")).unwrap();
        let child = tree.insert_child(root, element("child")).unwrap();
        let grandchild = tree.insert_child(child, element("grandchild")).unwrap();

        let mut limits = ValidationLimits::small();
        limits.max_nodes = 3;
        limits.max_tree_depth = 0;
        assert_eq!(
            tree.validate_with_limits(&limits).unwrap_err().code(),
            "model.validation.limit-tree-depth"
        );

        limits.max_tree_depth = 1;
        assert_eq!(
            tree.validate_with_limits(&limits).unwrap_err().code(),
            "model.validation.limit-tree-depth"
        );

        limits.max_tree_depth = 2;
        assert!(tree.validate_with_limits(&limits).is_ok());
        assert_eq!(tree.depth(root).unwrap(), 0);
        assert_eq!(tree.depth(child).unwrap(), 1);
        assert_eq!(tree.depth(grandchild).unwrap(), 2);
    }

    #[test]
    fn deeply_nested_properties_validate_iteratively_and_reject_at_boundary() {
        let depth = 4_096usize;
        let mut value = PropertyValue::string("leaf");
        for index in (0..depth).rev() {
            let mut nested = ElementProperty::new(format!("nested-{index}"));
            nested.properties.insert("child", value);
            value = PropertyValue::Element(nested);
        }

        let mut item = element("deep-properties");
        item.set_property("root", value);
        let mut limits = ValidationLimits::small();
        limits.max_nodes = 1;
        limits.max_property_depth = depth;
        assert!(item.validate_with_limits(&limits).is_ok());

        limits.max_property_depth = depth - 1;
        assert_eq!(
            item.validate_with_limits(&limits).unwrap_err().code(),
            "model.validation.limit-property-depth"
        );
    }

    #[test]
    fn deeply_nested_tree_validation_rejects_without_recursive_stack_use() {
        let depth = 20_000usize;
        let mut tree = IdentityTree::<usize>::new();
        let mut current = tree.insert_root(0).unwrap();
        for value in 1..=depth {
            current = tree.insert_child(current, value).unwrap();
        }

        let mut limits = ValidationLimits::small();
        limits.max_nodes = depth + 1;
        limits.max_tree_depth = depth - 1;
        assert_eq!(
            tree.validate_bounded(&limits).unwrap_err().code(),
            "model.validation.limit-tree-depth"
        );
    }

    #[test]
    fn bounded_queries_do_not_overallocate_and_hash_views_are_distinct() {
        let mut tree = IdentityTree::<u32>::new();
        let first = tree.insert_root(1).unwrap();
        let second = tree.insert_root(2).unwrap();
        let child = tree.insert_child(first, 3).unwrap();
        assert_eq!(
            tree.get_array_bounded(1),
            Err(TreeError::QueryLimitExceeded {
                operation: "get_array",
                limit: 1
            })
        );
        assert_eq!(
            tree.preorder_ids_bounded(2),
            Err(TreeError::QueryLimitExceeded {
                operation: "preorder_ids",
                limit: 2
            })
        );
        assert_eq!(
            tree.find_all_bounded(1, |_| true),
            Err(TreeError::QueryLimitExceeded {
                operation: "find_all",
                limit: 1
            })
        );
        assert_eq!(
            tree.path_to_bounded(child, 1),
            Err(TreeError::QueryLimitExceeded {
                operation: "path_to",
                limit: 1
            })
        );

        let mut listed = ListedHashTree::<u32>::new();
        let listed_first = listed.insert_root(10).unwrap();
        let listed_second = listed.insert_root(20).unwrap();
        assert_eq!(listed.root_ids(), &[listed_first, listed_second]);

        let mut hash = HashTree::<u32>::new();
        let high = NodeId::new(20);
        let low = NodeId::new(10);
        hash.insert_with_id(None, high, 20).unwrap();
        hash.add_with_id(None, low, 10).unwrap();
        assert_eq!(hash.root_ids(), &[low, high]);
        assert_eq!(hash.add_with_id(None, low, 999), Ok(low));
        assert_eq!(hash.value(low), Ok(&10));
        let fresh = hash.add_fresh(None, 30).unwrap();
        assert_ne!(fresh, low);
        assert_eq!(hash.value(fresh), Ok(&30));
        assert_eq!(hash.merge_with_id(None, low, 999), Ok(low));
        assert_eq!(hash.value(low), Ok(&10));
        assert_eq!(
            hash.add_with_id(Some(high), low, 10),
            Err(TreeError::ParentMismatch {
                id: low,
                expected: None,
                actual: Some(high)
            })
        );
        assert_ne!(
            ListedHashTree::from_tree(tree),
            ListedHashTree::from_tree(hash.into_tree())
        );
        assert_eq!(second, NodeId::new(2));
    }

    #[test]
    fn lossless_wire_capability_stays_at_the_jmx_boundary() {
        let error = ModelCapabilityError::UnsupportedLosslessWire {
            context: "XML sidecars are owned by jmeter-rs-jmx",
        };
        assert_eq!(error.code(), "model.capability.unsupported-lossless-wire");
        assert!(error.to_string().contains("pure model"));
        let common: ModelError = error.into();
        assert_eq!(common.code(), "model.capability.unsupported-lossless-wire");
    }

    #[test]
    fn debug_redacts_opaque_property_and_element_payloads() {
        let secret = "debug-secret-payload";
        let opaque = OpaqueValue::text("plugin.Secret", secret);
        let opaque_debug = format!("{opaque:?}");
        assert!(!opaque_debug.contains(secret));
        assert!(opaque_debug.contains("raw_len: 20"));
        assert!(opaque_debug.contains("<redacted>"));
        let large_debug = format!(
            "{:?}",
            OpaqueValue::new("plugin.Secret", vec![0_u8; 16 * 1024])
        );
        assert!(large_debug.len() < 256);

        let object = ObjectProperty::opaque_xml(
            "plugin.Secret",
            secret.as_bytes().to_vec(),
            [ObjectPropertyAttribute::new("token", secret)],
        );
        let object_debug = format!("{object:?}");
        assert!(!object_debug.contains(secret));
        assert!(object_debug.contains("raw_len: 20"));
        assert!(object_debug.contains("raw: \"<redacted>\""));

        let attribute_debug = format!("{:?}", ObjectPropertyAttribute::new("token", secret));
        assert!(!attribute_debug.contains(secret));
        assert!(attribute_debug.contains("value: \"<redacted>\""));

        let property_debug = format!("{:?}", PropertyValue::opaque("plugin.Secret", secret));
        assert!(!property_debug.contains(secret));

        let mut element = element("debug-redaction");
        element.set_property("opaque", PropertyValue::Object(object));
        element.push_opaque_extension(opaque);
        let element_debug = format!("{element:?}");
        assert!(!element_debug.contains(secret));
        assert!(element_debug.contains("properties_len: 1"));
        assert!(element_debug.contains("opaque_extensions_len: 1"));
    }

    #[test]
    fn debug_is_metadata_only_for_nested_public_model_values() {
        let secret = "model-debug-secret";
        let metadata = ElementMetadata::new(secret, secret, secret);
        let metadata_debug = format!("{metadata:?}");
        assert!(!metadata_debug.contains(secret));
        assert!(metadata_debug.contains("test_class_len: 18"));

        let source = SourceLocation::new(7, 3)
            .expect("positive source coordinates")
            .with_source(secret)
            .with_byte_offset(42);
        let source_debug = format!("{source:?}");
        assert!(!source_debug.contains(secret));
        assert!(source_debug.contains("source_present: true"));
        assert!(source_debug.contains("source_len: Some(18)"));

        let nested = ElementProperty::new(secret).with_class_name(secret);
        let nested_debug = format!("{nested:?}");
        assert!(!nested_debug.contains(secret));
        assert!(nested_debug.contains("properties_len: 0"));

        let mut properties = Properties::new();
        properties.insert(secret, PropertyValue::string(secret));
        let properties_debug = format!("{properties:?}");
        assert!(!properties_debug.contains(secret));
        assert!(properties_debug.contains("entries_len: 1"));

        let property_entry = PropertyEntry::new(secret, PropertyValue::string(secret));
        let property_entry_debug = format!("{property_entry:?}");
        assert!(!property_entry_debug.contains(secret));
        assert!(property_entry_debug.contains("name_len: 18"));

        let error_debug = format!(
            "{:?}",
            PropertyError::DuplicateName {
                name: secret.to_owned(),
            }
        );
        assert!(!error_debug.contains(secret));
        assert!(error_debug.contains("name_len: 18"));

        let values = [
            PropertyValue::string(secret),
            PropertyValue::Object(ObjectProperty::text(secret, secret)),
            PropertyValue::Element(nested),
            PropertyValue::opaque_text(secret, secret),
        ];
        for value in values {
            let debug = format!("{value:?}");
            assert!(!debug.contains(secret), "debug leaked {debug}");
        }

        let mut test_element = TestElement::new(metadata);
        test_element.set_property(secret, PropertyValue::string(secret));
        test_element.set_temporary_property(secret, PropertyValue::string(secret));
        test_element.set_source_location(source);
        let element_debug = format!("{test_element:?}");
        assert!(!element_debug.contains(secret));
        assert!(element_debug.contains("running_version_present: false"));
    }

    #[test]
    fn object_property_class_attribute_absent_and_empty_are_distinct() {
        let absent = ObjectProperty::from_optional_class_name(None, b"payload".to_vec());
        let empty =
            ObjectProperty::from_optional_class_name(Some(String::new()), b"payload".to_vec());
        let present = ObjectProperty::new("plugin.Type", b"payload".to_vec());

        assert_eq!(absent.class_name, None);
        assert_eq!(empty.class_name, Some(String::new()));
        assert_eq!(present.class_name, Some("plugin.Type".to_owned()));
        assert_ne!(absent, empty);
        assert_ne!(empty, present);
        assert_eq!(
            ObjectProperty::without_class_name(b"payload".to_vec()),
            absent
        );
        assert_eq!(
            present.clone().without_class_attribute(),
            ObjectProperty::without_class_name(b"payload".to_vec())
                .with_payload_kind(ObjectPayloadKind::Text)
        );
        assert_eq!(
            absent
                .clone()
                .with_optional_class_name(Some("plugin.Type".to_owned()))
                .class_name(),
            Some("plugin.Type")
        );
    }

    #[test]
    fn property_kinds_have_distinct_constructors_and_accessors() {
        let null = PropertyValue::null();
        assert_eq!(null.kind(), PropertyKind::Null);
        assert_eq!(null.as_null(), Ok(()));

        let string = PropertyValue::string("value");
        assert_eq!(string.kind(), PropertyKind::String);
        assert_eq!(string.as_str(), Ok("value"));

        let boolean = PropertyValue::boolean(true);
        assert_eq!(boolean.kind(), PropertyKind::Boolean);
        assert_eq!(boolean.as_bool(), Ok(true));

        let integer = PropertyValue::integer(-7);
        assert_eq!(integer.kind(), PropertyKind::Integer);
        assert_eq!(integer.as_i32(), Ok(-7));

        let long = PropertyValue::long(-9);
        assert_eq!(long.kind(), PropertyKind::Long);
        assert_eq!(long.as_i64(), Ok(-9));

        let float = PropertyValue::float(f32::from_bits(0x3f80_0001));
        assert_eq!(float.kind(), PropertyKind::Float);
        assert_eq!(PropertyKind::Float.to_string(), "float");
        assert_eq!(float.as_f32(), Ok(f32::from_bits(0x3f80_0001)));

        let double = PropertyValue::double(-0.25);
        assert_eq!(double.kind(), PropertyKind::Double);
        assert_eq!(double.as_f64(), Ok(-0.25));

        let collection = PropertyValue::collection(vec![PropertyValue::integer(1)]);
        assert_eq!(collection.kind(), PropertyKind::Collection);
        assert_eq!(
            collection.as_collection().unwrap(),
            &[PropertyValue::integer(1)]
        );

        let named_collection = PropertyValue::named_collection(vec![PropertyEntry::new(
            "entry",
            PropertyValue::boolean(false),
        )]);
        assert_eq!(named_collection.kind(), PropertyKind::NamedCollection);
        assert_eq!(
            named_collection.as_named_collection().unwrap()[0].name,
            "entry"
        );

        let map = PropertyValue::map(vec![PropertyEntry::new(
            "mapped",
            PropertyValue::string("value"),
        )]);
        assert_eq!(map.kind(), PropertyKind::Map);
        assert_eq!(map.as_map().unwrap()[0].name, "mapped");

        let object = PropertyValue::Object(ObjectProperty::text("example.Type", "raw"));
        assert_eq!(object.kind(), PropertyKind::Object);
        assert_eq!(
            object.as_object().unwrap().class_name,
            Some("example.Type".to_owned())
        );

        let element = PropertyValue::Element(ElementProperty::new("nested"));
        assert_eq!(element.kind(), PropertyKind::Element);
        assert_eq!(element.as_element().unwrap().name, "nested");

        let opaque = PropertyValue::opaque("plugin.Value", vec![1, 2, 3]);
        assert_eq!(opaque.kind(), PropertyKind::Opaque);
        assert_eq!(opaque.as_opaque().unwrap().raw, vec![1, 2, 3]);

        assert_eq!(
            float.as_double(),
            Err(PropertyTypeError {
                expected: PropertyKind::Double,
                actual: PropertyKind::Float,
            })
        );
        assert!(collection.as_named_collection().is_err());
        assert!(named_collection.as_collection().is_err());
    }

    #[test]
    fn collection_and_named_collection_retain_distinct_programmatic_contracts() {
        let positional = PropertyValue::collection(vec![
            PropertyValue::string("first"),
            PropertyValue::string("second"),
        ]);
        let named = PropertyValue::named_collection(vec![
            PropertyEntry::new("first-name", PropertyValue::string("first")),
            PropertyEntry::new("second-name", PropertyValue::string("second")),
        ]);

        assert_ne!(positional.kind(), named.kind());
        assert_eq!(
            positional.as_collection().unwrap(),
            &[
                PropertyValue::string("first"),
                PropertyValue::string("second"),
            ]
        );
        let named_entries = named.as_named_collection().unwrap();
        assert_eq!(
            named_entries
                .iter()
                .map(|entry| entry.name.as_str())
                .collect::<Vec<_>>(),
            vec!["first-name", "second-name"]
        );
        assert_eq!(
            named_entries
                .iter()
                .map(|entry| &entry.value)
                .collect::<Vec<_>>(),
            vec![
                &PropertyValue::string("first"),
                &PropertyValue::string("second"),
            ]
        );

        let positional_clone = positional.clone();
        let named_clone = named.clone();
        assert_eq!(positional_clone, positional);
        assert_eq!(named_clone, named);
        assert!(positional_clone.as_named_collection().is_err());
        assert!(named_clone.as_collection().is_err());
    }

    #[test]
    fn object_payload_metadata_is_opaque_ordered_and_cloneable() {
        let object = ObjectProperty::opaque_xml(
            "plugin.Type",
            vec![b'<', b'v', b'/', b'>'],
            vec![
                ObjectPropertyAttribute::new("class", "plugin.Type"),
                ObjectPropertyAttribute::new("custom", "  exact  "),
            ],
        );
        assert_eq!(object.payload_kind, ObjectPayloadKind::OpaqueXml);
        assert!(object.is_opaque_xml());
        assert_eq!(object.class_name(), Some("plugin.Type"));
        assert_eq!(object.raw_bytes(), b"<v/>");
        assert_eq!(object.raw(), b"<v/>");
        assert_eq!(object.raw, b"<v/>".to_vec());
        assert_eq!(object.attributes[1].value, "  exact  ");

        let text = ObjectProperty::text("plugin.Type", "text");
        assert_eq!(text.payload_kind, ObjectPayloadKind::Text);
        assert!(!text.is_opaque_xml());

        let mut cloned = object.clone();
        cloned.raw[0] = b'X';
        cloned.attributes[0].value = "changed".to_owned();
        assert_eq!(object.raw, b"<v/>".to_vec());
        assert_eq!(object.attributes[0].value, "plugin.Type");

        let configured = ObjectProperty::new("plugin.Type", b"raw".to_vec())
            .with_payload_kind(ObjectPayloadKind::OpaqueXml)
            .with_attributes(vec![ObjectPropertyAttribute::new("kind", "opaque")]);
        assert!(configured.is_opaque_xml());
        assert_eq!(configured.attributes[0].name, "kind");
        let opaque = OpaqueValue::new("plugin.Type", b"raw".to_vec());
        assert_eq!(opaque.raw_bytes(), b"raw");
        assert_eq!(opaque.raw(), b"raw");
        assert_eq!(opaque.clone().into_raw(), b"raw".to_vec());
    }

    #[test]
    fn properties_clone_and_mutation_preserve_order_independently() {
        let original = Properties::from_entries([
            PropertyEntry::new("first", PropertyValue::integer(1)),
            PropertyEntry::new("second", PropertyValue::integer(2)),
            PropertyEntry::new("third", PropertyValue::integer(3)),
        ])
        .unwrap();
        let mut cloned = original.clone();

        assert_eq!(
            original.keys().collect::<Vec<_>>(),
            vec!["first", "second", "third"]
        );
        assert_eq!(
            cloned.keys().collect::<Vec<_>>(),
            vec!["first", "second", "third"]
        );
        assert_eq!(
            cloned.insert("second", PropertyValue::integer(20)),
            Some(PropertyValue::integer(2))
        );
        assert_eq!(cloned.remove("first"), Some(PropertyValue::integer(1)));
        assert_eq!(cloned.insert("first", PropertyValue::integer(10)), None);
        assert_eq!(
            cloned.keys().collect::<Vec<_>>(),
            vec!["second", "third", "first"]
        );
        assert_eq!(original.get("first"), Some(&PropertyValue::integer(1)));
        assert_eq!(original.get("second"), Some(&PropertyValue::integer(2)));
        assert_eq!(
            original.keys().collect::<Vec<_>>(),
            vec!["first", "second", "third"]
        );
    }

    #[test]
    fn nested_typed_values_and_opaque_payloads_are_lossless() {
        let nested = ElementProperty::new("nested").with_class_name("plugin.Nested");
        let map = PropertyValue::Map(vec![
            PropertyEntry::new("empty", PropertyValue::String(String::new())),
            PropertyEntry::new("nested", PropertyValue::Element(nested)),
            PropertyEntry::new(
                "opaque",
                PropertyValue::Opaque(OpaqueValue::new("plugin.Custom", vec![0, 255, 7])),
            ),
        ]);
        let collection = PropertyValue::NamedCollection(vec![
            PropertyEntry::new("map", map.clone()),
            PropertyEntry::new("bool", PropertyValue::Boolean(false)),
        ]);
        assert_eq!(map.kind(), PropertyKind::Map);
        assert_eq!(collection.kind(), PropertyKind::NamedCollection);
        let PropertyValue::Map(entries) = map else {
            panic!("map kind must contain named entries");
        };
        assert_eq!(entries[0].name, "empty");
        assert_eq!(entries[1].name, "nested");
        assert_eq!(
            entries[2]
                .value
                .as_opaque()
                .ok()
                .and_then(OpaqueValue::as_text),
            None
        );
        let PropertyValue::Opaque(raw) = &entries[2].value else {
            panic!("opaque nested value must be retained");
        };
        assert_eq!(raw.raw, vec![0, 255, 7]);
    }

    #[test]
    fn element_running_version_and_clone_are_independent() {
        let mut original = element("same");
        original.set_property("a", PropertyValue::Integer(1));
        original.set_temporary_property("runtime", PropertyValue::String("before".to_owned()));
        original.set_running_version();
        original.set_enabled(false);
        original.set_property("a", PropertyValue::Integer(2));
        original.set_temporary_property("runtime", PropertyValue::String("after".to_owned()));
        assert!(original.recover_running_version());
        assert!(original.is_enabled());
        assert_eq!(original.property("a"), Some(&PropertyValue::Integer(1)));
        assert_eq!(
            original.temporary_property("runtime"),
            Some(&PropertyValue::String("before".to_owned()))
        );
        assert!(original.recover_running_version());

        let mut cloned = original.clone();
        cloned.set_property("a", PropertyValue::Integer(99));
        cloned.set_enabled(false);
        assert_eq!(original.property("a"), Some(&PropertyValue::Integer(1)));
        assert!(original.is_enabled());
        assert_eq!(cloned.property("a"), Some(&PropertyValue::Integer(99)));
        assert!(!cloned.is_enabled());
    }

    #[test]
    fn tree_preserves_duplicate_values_and_ordered_identity() {
        let mut tree = ElementTree::new();
        let first = tree.insert_root(element("duplicate")).unwrap();
        let second = tree.insert_root(element("duplicate")).unwrap();
        let child = tree.insert_child(first, element("child")).unwrap();
        let sibling = tree.insert_child(first, element("sibling")).unwrap();
        assert_ne!(first, second);
        assert_eq!(
            tree.lookup(first).unwrap().value(),
            tree.lookup(second).unwrap().value()
        );
        assert_eq!(tree.root_ids(), &[first, second]);
        assert_eq!(tree.children(first).unwrap(), &[child, sibling]);
        assert_eq!(tree.parent(child).unwrap(), Some(first));
        assert_eq!(tree.preorder_ids(), vec![first, child, sibling, second]);
        assert_eq!(
            tree.find_all(|node| node.value().name() == "duplicate"),
            vec![first, second]
        );
        assert_eq!(tree.path_to(sibling).unwrap(), vec![first, sibling]);
        assert_eq!(tree.depth(sibling).unwrap(), 1);
        assert!(tree.validate().is_ok());
    }

    #[test]
    fn tree_clone_preserves_identity_and_is_independent() {
        let mut original = IdentityTree::<u32>::new();
        let root = original.insert_root(1).unwrap();
        let child = original.insert_child(root, 2).unwrap();
        let mut cloned = original.cloned();

        assert_eq!(cloned.root_ids(), original.root_ids());
        assert_eq!(cloned.children(root).unwrap(), &[child]);
        assert_eq!(cloned.preorder_ids(), original.preorder_ids());

        assert_eq!(cloned.replace(root, 10), Ok(1));
        assert_eq!(cloned.remove_leaf(child), Ok(2));
        assert_eq!(original.value(root), Ok(&1));
        assert_eq!(original.children(root).unwrap(), &[child]);
        assert_eq!(cloned.value(root), Ok(&10));
        assert!(cloned.children(root).unwrap().is_empty());
        assert!(original.validate().is_ok());
        assert!(cloned.validate().is_ok());
    }

    #[test]
    fn tree_traversal_is_depth_first_and_iterative() {
        let mut tree = IdentityTree::<u32>::new();
        let root = tree.insert_root(0).unwrap();
        let first = tree.insert_child(root, 1).unwrap();
        let _second = tree.insert_child(root, 2).unwrap();
        let _grandchild = tree.insert_child(first, 3).unwrap();
        let mut events = Vec::new();
        let outcome = tree
            .traverse(|event| {
                events.push(event);
                TraversalControl::Continue
            })
            .unwrap();
        assert_eq!(
            outcome,
            TraversalOutcome {
                events: 8,
                entered: 4,
                stopped: false
            }
        );
        assert_eq!(
            events,
            vec![
                VisitEvent::Enter { id: root, depth: 0 },
                VisitEvent::Enter {
                    id: first,
                    depth: 1
                },
                VisitEvent::Enter {
                    id: NodeId::new(4),
                    depth: 2
                },
                VisitEvent::Leave {
                    id: NodeId::new(4),
                    depth: 2
                },
                VisitEvent::Leave {
                    id: first,
                    depth: 1
                },
                VisitEvent::Enter {
                    id: NodeId::new(3),
                    depth: 1
                },
                VisitEvent::Leave {
                    id: NodeId::new(3),
                    depth: 1
                },
                VisitEvent::Leave { id: root, depth: 0 },
            ]
        );
        let stopped = tree
            .traverse(|event| {
                if event.is_enter() {
                    TraversalControl::Stop
                } else {
                    TraversalControl::Continue
                }
            })
            .unwrap();
        assert_eq!(
            stopped,
            TraversalOutcome {
                events: 1,
                entered: 1,
                stopped: true
            }
        );
        let stopped_after_branch = tree
            .traverse(|event| {
                if matches!(event, VisitEvent::Enter { id, .. } if id == NodeId::new(3)) {
                    TraversalControl::Stop
                } else {
                    TraversalControl::Continue
                }
            })
            .unwrap();
        assert_eq!(stopped_after_branch.events, 6);
        assert_eq!(stopped_after_branch.entered_nodes(), 4);
        assert!(stopped_after_branch.stopped);
        let bounded = tree.traverse_bounded(3, |_| TraversalControl::Continue);
        assert_eq!(bounded, Err(TreeError::TraversalLimitExceeded { limit: 3 }));
    }

    #[test]
    fn traversal_resource_limit_is_checked_before_callback_delivery() {
        let mut tree = IdentityTree::<u32>::new();
        tree.insert_root(1).unwrap();

        let mut zero_callbacks = 0;
        assert_eq!(
            tree.traverse_bounded(0, |_| {
                zero_callbacks += 1;
                TraversalControl::Continue
            }),
            Err(TreeError::TraversalLimitExceeded { limit: 0 })
        );
        assert_eq!(zero_callbacks, 0);

        let mut one_callbacks = 0;
        assert_eq!(
            tree.traverse_bounded(1, |_| {
                one_callbacks += 1;
                TraversalControl::Continue
            }),
            Err(TreeError::TraversalLimitExceeded { limit: 1 })
        );
        assert_eq!(one_callbacks, 1);
    }

    #[test]
    fn tree_mutations_have_typed_failures_and_preserve_invariants() {
        let mut tree = IdentityTree::<u32>::new();
        let missing = tree.insert_child(NodeId::new(99), 1);
        assert_eq!(
            missing,
            Err(TreeError::ParentNotFound {
                id: NodeId::new(99)
            })
        );
        let root = tree.insert_root(1).unwrap();
        let child = tree.insert_child(root, 2).unwrap();
        let grandchild = tree.insert_child(child, 3).unwrap();
        assert_eq!(
            tree.remove_leaf(child),
            Err(TreeError::NodeHasChildren { id: child })
        );
        assert_eq!(tree.replace(root, 10), Ok(1));
        assert_eq!(tree.get(root).unwrap().value(), &10);
        assert_eq!(tree.children(root).unwrap(), &[child]);
        assert_eq!(tree.replace_subtree(root, 20), Ok(10));
        assert_eq!(tree.get(root).unwrap().value(), &20);
        assert!(tree.children(root).unwrap().is_empty());
        assert!(!tree.contains(child));
        assert!(!tree.contains(grandchild));
        assert_eq!(
            tree.remove(NodeId::new(99)),
            Err(TreeError::NodeNotFound {
                id: NodeId::new(99)
            })
        );
        assert_eq!(tree.remove(root), Ok(20));
        assert!(tree.is_empty());
        assert!(tree.validate().is_ok());
    }

    #[test]
    fn very_deep_trees_do_not_use_recursive_traversal() {
        let mut tree = IdentityTree::<usize>::new();
        let mut current = tree.insert_root(0).unwrap();
        let depth = 20_000usize;
        for value in 1..=depth {
            current = tree.insert_child(current, value).unwrap();
        }
        assert_eq!(tree.len(), depth + 1);
        assert_eq!(tree.depth(current).unwrap(), depth);
        let outcome = tree
            .traverse_bounded((depth + 1) * 2, |_| TraversalControl::Continue)
            .unwrap();
        assert_eq!(outcome.events, (depth + 1) * 2);
        assert_eq!(tree.preorder_ids().len(), depth + 1);
    }

    #[derive(Clone, Copy)]
    struct Deterministic(u64);

    impl Deterministic {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            self.0
        }
    }

    #[test]
    fn generated_trees_keep_order_parent_links_and_identity() {
        for seed in 0..32u64 {
            let mut random = Deterministic(seed + 1);
            let mut tree = IdentityTree::<u16>::new();
            let mut known = Vec::new();
            for _ in 0..128 {
                let parent = if known.is_empty() || random.next().is_multiple_of(4) {
                    None
                } else {
                    Some(known[(random.next() as usize) % known.len()])
                };
                let value = (random.next() & u16::MAX as u64) as u16;
                let id = tree.insert(parent, value).unwrap();
                known.push(id);
                assert!(tree.validate().is_ok());
            }
            assert_eq!(tree.preorder_ids().len(), known.len());
            let preorder = tree.preorder_ids();
            assert!(preorder.iter().all(|id| tree.contains(*id)));
            assert_eq!(preorder.len(), known.len());
            let clone = tree.cloned();
            assert_eq!(clone, tree);
            assert_eq!(clone.preorder_ids(), preorder);
        }
    }
}
