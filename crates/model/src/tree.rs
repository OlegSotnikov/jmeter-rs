// SPDX-License-Identifier: Apache-2.0
//! Ordered, identity-based semantic trees.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use crate::limits::ValidationState;
use crate::{
    ElementMetadata, ModelError, ModelValidationError, NodeId, SourceLocation, TestElement,
    TreeError, ValidationLimitKind, ValidationLimits,
};

/// One node stored by IdentityTree.
///
/// The node's ID is independent of value equality.  In particular, two
/// TestElements with the same metadata and properties still occupy distinct
/// nodes when inserted twice.
#[derive(Clone, PartialEq)]
pub struct TreeNode<T> {
    id: NodeId,
    parent: Option<NodeId>,
    value: T,
    children: Vec<NodeId>,
}

impl<T> fmt::Debug for TreeNode<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TreeNode")
            .field("id", &self.id)
            .field("parent_present", &self.parent.is_some())
            .field("children_len", &self.children.len())
            .field("value_present", &true)
            .finish()
    }
}

impl<T> TreeNode<T> {
    fn new(id: NodeId, parent: Option<NodeId>, value: T) -> Self {
        Self {
            id,
            parent,
            value,
            children: Vec::new(),
        }
    }

    /// Returns this node's document-local identity.
    #[must_use]
    pub const fn id(&self) -> NodeId {
        self.id
    }

    /// Returns the parent ID, or None for a root node.
    #[must_use]
    pub const fn parent(&self) -> Option<NodeId> {
        self.parent
    }

    /// Returns the stored value.
    #[must_use]
    pub const fn value(&self) -> &T {
        &self.value
    }

    /// Returns mutable access to the stored value.
    pub fn value_mut(&mut self) -> &mut T {
        &mut self.value
    }

    /// Returns child IDs in insertion order.
    #[must_use]
    pub fn children(&self) -> &[NodeId] {
        &self.children
    }

    /// Returns whether this node has no children.
    #[must_use]
    pub fn is_leaf(&self) -> bool {
        self.children.is_empty()
    }

    /// Returns this node's depth when the node is viewed from its parent links.
    ///
    /// The tree validates links while calculating the value; a malformed tree
    /// cannot be constructed through the safe API, so a cycle yields None
    /// instead of looping indefinitely.
    #[must_use]
    pub fn depth(&self, tree: &IdentityTree<T>) -> Option<usize> {
        tree.depth(self.id).ok()
    }
}

impl TreeNode<TestElement> {
    /// Returns the semantic element stored by this node.
    #[must_use]
    pub fn element(&self) -> &TestElement {
        self.value()
    }

    /// Returns exact test/gui/name metadata for this node.
    #[must_use]
    pub fn metadata(&self) -> &ElementMetadata {
        &self.value.metadata
    }

    /// Returns the source element's enabled state.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.value.enabled
    }

    /// Returns the source location attached to this node's element.
    #[must_use]
    pub fn source_location(&self) -> &SourceLocation {
        &self.value.source_location
    }
}

/// Compatibility alias for callers that use the shorter node name.
pub type Node<T> = TreeNode<T>;

/// A callback event emitted by IdentityTree::traverse.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum VisitEvent {
    /// Emitted before a node's children are visited.
    Enter {
        /// Entered node identity.
        id: NodeId,
        /// Zero-based node depth.
        depth: usize,
    },
    /// Emitted after all of a node's children have been visited.
    Leave {
        /// Left node identity.
        id: NodeId,
        /// Zero-based node depth.
        depth: usize,
    },
}

impl VisitEvent {
    /// Returns the node ID associated with the event.
    #[must_use]
    pub const fn id(self) -> NodeId {
        match self {
            Self::Enter { id, .. } | Self::Leave { id, .. } => id,
        }
    }

    /// Returns the zero-based tree depth associated with the event.
    #[must_use]
    pub const fn depth(self) -> usize {
        match self {
            Self::Enter { depth, .. } | Self::Leave { depth, .. } => depth,
        }
    }

    /// Returns whether this is an enter event.
    #[must_use]
    pub const fn is_enter(self) -> bool {
        matches!(self, Self::Enter { .. })
    }

    /// Returns whether this is a leave event.
    #[must_use]
    pub const fn is_leave(self) -> bool {
        matches!(self, Self::Leave { .. })
    }
}

/// Controls a callback-driven tree traversal.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TraversalControl {
    /// Continue to the next event.
    Continue,
    /// Stop after the current event and return a stopped outcome.
    Stop,
}

/// The result of a traversal callback sequence.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TraversalOutcome {
    /// Number of enter and leave events delivered to the callback.
    pub events: usize,
    /// Number of enter events delivered to the callback.
    pub entered: usize,
    /// Whether the callback requested an early stop.
    pub stopped: bool,
}

impl TraversalOutcome {
    /// Returns the number of nodes whose enter events were delivered.
    #[must_use]
    pub const fn entered_nodes(self) -> usize {
        self.entered
    }
}

/// An iterative preorder iterator over one tree's nodes.
///
/// The iterator uses a heap-backed explicit stack rather than recursive calls,
/// so a deeply nested input document cannot overflow the Rust call stack.  It
/// has no node/depth budget of its own and is therefore a trusted-tree
/// convenience; input-facing code should use [`IdentityTree::traverse_bounded`]
/// or [`IdentityTree::preorder_ids_bounded`] with caller-owned limits.
pub struct PreorderIter<'a, T> {
    tree: &'a IdentityTree<T>,
    next_root: usize,
    stack: Vec<PreorderFrame>,
}

struct PreorderFrame {
    id: NodeId,
    next_child: usize,
    yielded: bool,
}

struct TraversalFrame {
    id: NodeId,
    depth: usize,
    next_child: usize,
    entered: bool,
}

impl<'a, T> Iterator for PreorderIter<'a, T> {
    type Item = &'a TreeNode<T>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.stack.is_empty() {
                let id = *self.tree.roots.get(self.next_root)?;
                self.next_root = self.next_root.saturating_add(1);
                self.stack.push(PreorderFrame {
                    id,
                    next_child: 0,
                    yielded: false,
                });
            }

            let frame = self.stack.last_mut()?;
            let node = self.tree.nodes.get(&frame.id)?;
            if !frame.yielded {
                frame.yielded = true;
                return Some(node);
            }
            if let Some(child) = node.children.get(frame.next_child).copied() {
                frame.next_child = frame.next_child.saturating_add(1);
                self.stack.push(PreorderFrame {
                    id: child,
                    next_child: 0,
                    yielded: false,
                });
            } else {
                self.stack.pop();
            }
        }
    }
}

/// An ordered tree whose node identity is independent of stored value equality.
///
/// BTreeMap is used only as an identity index.  Semantic order is always
/// carried by roots and each node's children vector; no observable order is
/// derived from map iteration.
#[derive(Clone, PartialEq)]
pub struct IdentityTree<T = TestElement> {
    nodes: BTreeMap<NodeId, TreeNode<T>>,
    roots: Vec<NodeId>,
    next_id: Option<u64>,
}

impl<T> fmt::Debug for IdentityTree<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IdentityTree")
            .field("nodes_len", &self.nodes.len())
            .field("roots_len", &self.roots.len())
            .field("next_id_present", &self.next_id.is_some())
            .finish()
    }
}

impl<T> Default for IdentityTree<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> IdentityTree<T> {
    /// Creates an empty tree.  Automatically allocated IDs start at one.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            nodes: BTreeMap::new(),
            roots: Vec::new(),
            next_id: Some(1),
        }
    }

    /// Returns the number of nodes in the tree.
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Returns whether the tree has no nodes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Returns root IDs in insertion order.
    #[must_use]
    pub fn root_ids(&self) -> &[NodeId] {
        &self.roots
    }

    /// Alias for IdentityTree::root_ids.
    #[must_use]
    pub fn roots(&self) -> &[NodeId] {
        self.root_ids()
    }

    /// Alias matching JMeter's listed-tree terminology for the current roots.
    #[must_use]
    pub fn list(&self) -> &[NodeId] {
        self.root_ids()
    }

    /// Returns a copied root list, analogous to a Java array snapshot.
    ///
    /// This convenience allocates for every root and is intended for trusted,
    /// already-bounded trees.  Input-facing code should use
    /// [`IdentityTree::get_array_bounded`] instead.
    #[must_use]
    pub fn get_array(&self) -> Vec<NodeId> {
        self.root_ids().to_vec()
    }

    /// Returns a copied root list only when it fits the caller's allocation
    /// budget.
    pub fn get_array_bounded(&self, max_roots: usize) -> Result<Vec<NodeId>, TreeError> {
        if self.roots.len() > max_roots {
            return Err(TreeError::QueryLimitExceeded {
                operation: "get_array",
                limit: max_roots,
            });
        }
        Ok(self.roots.clone())
    }

    /// Returns whether a node ID is present.
    #[must_use]
    pub fn contains(&self, id: NodeId) -> bool {
        self.nodes.contains_key(&id)
    }

    /// Looks up a node without panicking on a missing ID.
    #[must_use]
    pub fn get(&self, id: NodeId) -> Option<&TreeNode<T>> {
        self.nodes.get(&id)
    }

    /// Returns a node's value without exposing the tree's identity index.
    pub fn value(&self, id: NodeId) -> Result<&T, TreeError> {
        Ok(self.lookup(id)?.value())
    }

    /// Looks up a mutable node without panicking on a missing ID.
    pub fn get_mut(&mut self, id: NodeId) -> Option<&mut TreeNode<T>> {
        self.nodes.get_mut(&id)
    }

    /// Looks up a node and returns a typed error when it is absent.
    pub fn lookup(&self, id: NodeId) -> Result<&TreeNode<T>, TreeError> {
        self.get(id).ok_or(TreeError::NodeNotFound { id })
    }

    /// Alias for IdentityTree::lookup.
    pub fn node(&self, id: NodeId) -> Result<&TreeNode<T>, TreeError> {
        self.lookup(id)
    }

    /// Looks up a mutable node and returns a typed error when it is absent.
    pub fn lookup_mut(&mut self, id: NodeId) -> Result<&mut TreeNode<T>, TreeError> {
        self.get_mut(id).ok_or(TreeError::NodeNotFound { id })
    }

    /// Returns a node's parent ID.
    pub fn parent(&self, id: NodeId) -> Result<Option<NodeId>, TreeError> {
        Ok(self.lookup(id)?.parent())
    }

    /// Returns child IDs in insertion order.
    pub fn children(&self, id: NodeId) -> Result<&[NodeId], TreeError> {
        Ok(self.lookup(id)?.children())
    }

    /// Returns whether a node has no children.
    pub fn is_leaf(&self, id: NodeId) -> Result<bool, TreeError> {
        Ok(self.lookup(id)?.is_leaf())
    }

    /// Inserts a fresh node under parent, or as a root when parent is None.
    pub fn insert(&mut self, parent: Option<NodeId>, value: T) -> Result<NodeId, TreeError> {
        if let Some(parent) = parent {
            self.require_parent(parent)?;
        }
        let id = self.allocate_id()?;
        self.insert_with_id(parent, id, value)?;
        Ok(id)
    }

    /// Inserts a fresh root node.
    pub fn insert_root(&mut self, value: T) -> Result<NodeId, TreeError> {
        self.insert(None, value)
    }

    /// Inserts a fresh child node under an existing parent.
    pub fn insert_child(&mut self, parent: NodeId, value: T) -> Result<NodeId, TreeError> {
        self.insert(Some(parent), value)
    }

    /// Alias for inserting a node under an optional parent.
    pub fn add(&mut self, parent: Option<NodeId>, value: T) -> Result<NodeId, TreeError> {
        self.insert(parent, value)
    }

    /// Inserts a node using a caller-supplied document-local identity.
    ///
    /// This is useful when an importer already has IDs to restore.  The ID must
    /// be unique in this tree; duplicate-looking values do not conflict.
    pub fn insert_with_id(
        &mut self,
        parent: Option<NodeId>,
        id: NodeId,
        value: T,
    ) -> Result<NodeId, TreeError> {
        if self.nodes.contains_key(&id) {
            return Err(TreeError::DuplicateNodeId { id });
        }
        if let Some(parent) = parent {
            self.require_parent(parent)?;
        }

        let node = TreeNode::new(id, parent, value);
        self.nodes.insert(id, node);
        if let Some(parent) = parent {
            // The parent was checked above and the map entry is private, so a
            // missing entry here would indicate an internal invariant failure.
            let Some(parent_node) = self.nodes.get_mut(&parent) else {
                return Err(TreeError::InvariantViolation {
                    detail: "validated parent disappeared during insertion",
                });
            };
            parent_node.children.push(id);
        } else {
            self.roots.push(id);
        }
        self.advance_allocator_past(id);
        Ok(id)
    }

    /// Replaces a node's value while retaining its identity, parent, and
    /// ordered children.
    pub fn replace(&mut self, id: NodeId, value: T) -> Result<T, TreeError> {
        let node = self.lookup_mut(id)?;
        Ok(std::mem::replace(&mut node.value, value))
    }

    /// Replaces a node's value and removes its entire child subtree.
    ///
    /// This is the explicit set-style operation corresponding to an upstream
    /// hash-tree replacement.  The node's own identity and parent position are
    /// retained; all descendants are discarded.
    pub fn replace_subtree(&mut self, id: NodeId, value: T) -> Result<T, TreeError> {
        self.lookup(id)?;
        self.clear_children(id)?;
        self.replace(id, value)
    }

    /// Alias for IdentityTree::replace_subtree.
    pub fn set(&mut self, id: NodeId, value: T) -> Result<T, TreeError> {
        self.replace_subtree(id, value)
    }

    /// Removes a node and all descendants, returning the removed node's value.
    pub fn remove(&mut self, id: NodeId) -> Result<T, TreeError> {
        self.remove_subtree(id)
    }

    /// Removes a node and all descendants, returning the removed node's value.
    pub fn remove_subtree(&mut self, id: NodeId) -> Result<T, TreeError> {
        self.lookup(id)?;
        let ids = self.collect_subtree_ids(id)?;
        let parent = self
            .nodes
            .get(&id)
            .ok_or(TreeError::NodeNotFound { id })?
            .parent;

        if let Some(parent) = parent {
            let Some(parent_node) = self.nodes.get_mut(&parent) else {
                return Err(TreeError::InvariantViolation {
                    detail: "child node points to a missing parent",
                });
            };
            parent_node.children.retain(|child| *child != id);
        } else {
            self.roots.retain(|root| *root != id);
        }

        let mut removed_value = None;
        for current in ids {
            if let Some(node) = self.nodes.remove(&current)
                && current == id
            {
                removed_value = Some(node.value);
            }
        }
        removed_value.ok_or(TreeError::InvariantViolation {
            detail: "subtree root disappeared during removal",
        })
    }

    /// Removes only a leaf node, returning its value.
    pub fn remove_leaf(&mut self, id: NodeId) -> Result<T, TreeError> {
        if !self.lookup(id)?.is_leaf() {
            return Err(TreeError::NodeHasChildren { id });
        }
        self.remove_subtree(id)
    }

    /// Removes all descendants of a node and returns their count.
    pub fn clear_children(&mut self, id: NodeId) -> Result<usize, TreeError> {
        let children = self.lookup(id)?.children.clone();
        let mut removed = 0;
        for child in children {
            let subtree_size = self.collect_subtree_ids(child)?.len();
            self.remove_subtree(child)?;
            removed += subtree_size;
        }
        if let Some(node) = self.nodes.get_mut(&id) {
            node.children.clear();
        }
        Ok(removed)
    }

    /// Returns an iterative preorder iterator preserving root and child order.
    #[must_use]
    pub fn iter_preorder(&self) -> PreorderIter<'_, T> {
        PreorderIter {
            tree: self,
            next_root: 0,
            stack: Vec::new(),
        }
    }

    /// Alias for the iterative preorder iterator.
    ///
    /// This unbounded convenience is trusted-tree-only; input-facing code
    /// should use [`IdentityTree::traverse_bounded`] or
    /// [`IdentityTree::preorder_ids_bounded`].
    #[must_use]
    pub fn iter(&self) -> PreorderIter<'_, T> {
        self.iter_preorder()
    }

    /// Returns all node IDs in preorder.
    ///
    /// This convenience allocates for the complete tree and is intended for
    /// trusted, already-bounded trees.  Input-facing code should use
    /// [`IdentityTree::preorder_ids_bounded`] instead.
    #[must_use]
    pub fn preorder_ids(&self) -> Vec<NodeId> {
        self.iter_preorder().map(TreeNode::id).collect()
    }

    /// Returns preorder IDs only when the result fits the caller's allocation
    /// budget.  The iterator itself uses only depth-bounded stack space.
    pub fn preorder_ids_bounded(&self, max_nodes: usize) -> Result<Vec<NodeId>, TreeError> {
        let mut ids = Vec::with_capacity(max_nodes.min(self.nodes.len()));
        for node in self.iter_preorder() {
            if ids.len() == max_nodes {
                return Err(TreeError::QueryLimitExceeded {
                    operation: "preorder_ids",
                    limit: max_nodes,
                });
            }
            ids.push(node.id());
        }
        Ok(ids)
    }

    /// Traverses the tree depth-first, emitting enter and leave events.
    ///
    /// Traversal is iterative and therefore safe for deeply nested,
    /// input-driven trees.  This unbounded convenience is intended for
    /// trusted, already-bounded trees; use [`IdentityTree::traverse_bounded`]
    /// at an input boundary.  The callback may stop early by returning
    /// TraversalControl::Stop.
    pub fn traverse<F>(&self, visitor: F) -> Result<TraversalOutcome, TreeError>
    where
        F: FnMut(VisitEvent) -> TraversalControl,
    {
        self.traverse_bounded(usize::MAX, visitor)
    }

    /// Traverses the tree while ignoring callback control.
    pub fn visit<F>(&self, mut visitor: F) -> Result<TraversalOutcome, TreeError>
    where
        F: FnMut(VisitEvent),
    {
        self.traverse(|event| {
            visitor(event);
            TraversalControl::Continue
        })
    }

    /// Traverses the tree with a maximum number of callback events.
    ///
    /// A limit of zero is valid and fails before delivering the first event.
    /// This guard is useful when a caller applies a resource budget to an
    /// untrusted or generated tree.
    pub fn traverse_bounded<F>(
        &self,
        max_events: usize,
        mut visitor: F,
    ) -> Result<TraversalOutcome, TreeError>
    where
        F: FnMut(VisitEvent) -> TraversalControl,
    {
        let mut next_root = 0usize;
        let mut stack = Vec::new();
        let mut events = 0usize;
        let mut entered = 0usize;

        loop {
            if stack.is_empty() {
                let Some(id) = self.roots.get(next_root).copied() else {
                    break;
                };
                next_root = next_root.saturating_add(1);
                stack.push(TraversalFrame {
                    id,
                    depth: 0,
                    next_child: 0,
                    entered: false,
                });
            }

            let (event, child) = {
                let frame = stack.last_mut().ok_or(TreeError::InvariantViolation {
                    detail: "traversal frame stack unexpectedly empty",
                })?;
                let node = self
                    .nodes
                    .get(&frame.id)
                    .ok_or(TreeError::InvariantViolation {
                        detail: "ordered link points to a missing node during traversal",
                    })?;
                if !frame.entered {
                    frame.entered = true;
                    (
                        Some(VisitEvent::Enter {
                            id: frame.id,
                            depth: frame.depth,
                        }),
                        None,
                    )
                } else if let Some(child) = node.children.get(frame.next_child).copied() {
                    frame.next_child = frame.next_child.saturating_add(1);
                    (None, Some((child, frame.depth.saturating_add(1))))
                } else {
                    let event = VisitEvent::Leave {
                        id: frame.id,
                        depth: frame.depth,
                    };
                    stack.pop();
                    (Some(event), None)
                }
            };

            if let Some((child, depth)) = child {
                stack.push(TraversalFrame {
                    id: child,
                    depth,
                    next_child: 0,
                    entered: false,
                });
                continue;
            }

            let Some(event) = event else {
                return Err(TreeError::InvariantViolation {
                    detail: "traversal produced neither event nor child",
                });
            };
            if events >= max_events {
                return Err(TreeError::TraversalLimitExceeded { limit: max_events });
            }
            events += 1;
            if event.is_enter() {
                entered += 1;
            }
            if matches!(visitor(event), TraversalControl::Stop) {
                return Ok(TraversalOutcome {
                    events,
                    entered,
                    stopped: true,
                });
            }
        }

        Ok(TraversalOutcome {
            events,
            entered,
            stopped: false,
        })
    }

    /// Finds the first node satisfying a predicate in preorder.
    ///
    /// This convenience has no traversal budget and is trusted-tree-only;
    /// input-facing code should use [`IdentityTree::traverse_bounded`] when a
    /// predicate can be evaluated from visit events.
    pub fn find<F>(&self, mut predicate: F) -> Option<NodeId>
    where
        F: FnMut(&TreeNode<T>) -> bool,
    {
        self.iter_preorder()
            .find(|node| predicate(node))
            .map(TreeNode::id)
    }

    /// Finds every node satisfying a predicate in preorder.
    ///
    /// This convenience allocates for every match and is intended for trusted,
    /// already-bounded trees.  Input-facing code should use
    /// [`IdentityTree::find_all_bounded`] instead.
    pub fn find_all<F>(&self, mut predicate: F) -> Vec<NodeId>
    where
        F: FnMut(&TreeNode<T>) -> bool,
    {
        self.iter_preorder()
            .filter(|node| predicate(node))
            .map(TreeNode::id)
            .collect()
    }

    /// Finds matching nodes only when the result fits the caller's allocation
    /// budget.
    pub fn find_all_bounded<F>(
        &self,
        max_results: usize,
        mut predicate: F,
    ) -> Result<Vec<NodeId>, TreeError>
    where
        F: FnMut(&TreeNode<T>) -> bool,
    {
        let mut ids = Vec::with_capacity(max_results.min(self.nodes.len()));
        for node in self.iter_preorder() {
            if predicate(node) {
                if ids.len() == max_results {
                    return Err(TreeError::QueryLimitExceeded {
                        operation: "find_all",
                        limit: max_results,
                    });
                }
                ids.push(node.id());
            }
        }
        Ok(ids)
    }

    /// Returns the root-to-node path in insertion/tree order.
    ///
    /// This convenience permits an unbounded result allocation and is intended
    /// for trusted, already-bounded trees.  Input-facing code should use
    /// [`IdentityTree::path_to_bounded`] instead.
    pub fn path_to(&self, id: NodeId) -> Result<Vec<NodeId>, TreeError> {
        self.path_to_bounded(id, usize::MAX)
    }

    /// Returns a root-to-node path only when it fits the caller's allocation
    /// budget.
    pub fn path_to_bounded(
        &self,
        id: NodeId,
        max_path_nodes: usize,
    ) -> Result<Vec<NodeId>, TreeError> {
        self.lookup(id)?;
        let mut path = Vec::with_capacity(max_path_nodes.min(self.nodes.len()));
        let mut current = Some(id);
        let limit = self.nodes.len();
        while let Some(node_id) = current {
            if path.len() >= limit {
                return Err(TreeError::InvariantViolation {
                    detail: "parent links contain a cycle",
                });
            }
            if path.len() == max_path_nodes {
                return Err(TreeError::QueryLimitExceeded {
                    operation: "path_to",
                    limit: max_path_nodes,
                });
            }
            let node = self
                .nodes
                .get(&node_id)
                .ok_or(TreeError::InvariantViolation {
                    detail: "parent link points to a missing node",
                })?;
            path.push(node_id);
            current = node.parent;
        }
        path.reverse();
        Ok(path)
    }

    /// Returns a node's zero-based depth.
    ///
    /// This convenience follows parent links without a caller budget and is
    /// intended for trusted, already-bounded trees.  Input-facing code should
    /// use [`IdentityTree::path_to_bounded`] when it needs the path itself.
    pub fn depth(&self, id: NodeId) -> Result<usize, TreeError> {
        self.path_to(id).map(|path| path.len().saturating_sub(1))
    }

    /// Checks parent/child links and ordered root membership.
    ///
    /// This structural check has no caller-supplied resource budget and is a
    /// trusted-model convenience.  Input-facing code should use
    /// [`IdentityTree::validate_bounded`] so both node count and tree depth are
    /// bounded.
    pub fn validate(&self) -> Result<(), TreeError> {
        let mut seen = BTreeSet::new();
        for root in &self.roots {
            let Some(node) = self.nodes.get(root) else {
                return Err(TreeError::InvariantViolation {
                    detail: "root list points to a missing node",
                });
            };
            if node.parent.is_some() || !seen.insert(*root) {
                return Err(TreeError::InvariantViolation {
                    detail: "root has a parent or appears twice",
                });
            }
        }
        for (id, node) in &self.nodes {
            if node.id != *id {
                return Err(TreeError::InvariantViolation {
                    detail: "identity index key differs from node ID",
                });
            }
            for child in &node.children {
                let Some(child_node) = self.nodes.get(child) else {
                    return Err(TreeError::InvariantViolation {
                        detail: "child list points to a missing node",
                    });
                };
                if child_node.parent != Some(*id) || !seen.insert(*child) {
                    return Err(TreeError::InvariantViolation {
                        detail: "child parent link is inconsistent or duplicated",
                    });
                }
            }
        }
        if seen.len() != self.nodes.len() {
            return Err(TreeError::InvariantViolation {
                detail: "a node is unreachable from the roots",
            });
        }
        Ok(())
    }

    /// Validates structural invariants after checking the node allocation
    /// budget.  Use the `TestElement` specialization for property/string
    /// limits as well.
    pub fn validate_bounded(&self, limits: &ValidationLimits) -> Result<(), ModelError> {
        if self.nodes.len() > limits.max_nodes {
            return Err(ModelValidationError::LimitExceeded {
                kind: ValidationLimitKind::Nodes,
                limit: limits.max_nodes,
                actual: self.nodes.len(),
            }
            .into());
        }
        self.validate().map_err(ModelError::from)?;
        self.validate_tree_depth(limits.max_tree_depth)
    }

    fn validate_tree_depth(&self, max_depth: usize) -> Result<(), ModelError> {
        let mut pending = self
            .roots
            .iter()
            .rev()
            .map(|id| (*id, 0usize))
            .collect::<Vec<_>>();
        while let Some((id, depth)) = pending.pop() {
            if depth > max_depth {
                return Err(ModelValidationError::LimitExceeded {
                    kind: ValidationLimitKind::TreeDepth,
                    limit: max_depth,
                    actual: depth,
                }
                .into());
            }
            let node = self.nodes.get(&id).ok_or_else(|| {
                ModelError::from(TreeError::InvariantViolation {
                    detail: "ordered link points to a missing node during depth validation",
                })
            })?;
            for child in node.children.iter().rev() {
                pending.push((*child, depth.saturating_add(1)));
            }
        }
        Ok(())
    }

    fn require_parent(&self, parent: NodeId) -> Result<(), TreeError> {
        if self.nodes.contains_key(&parent) {
            Ok(())
        } else {
            Err(TreeError::ParentNotFound { id: parent })
        }
    }

    fn allocate_id(&mut self) -> Result<NodeId, TreeError> {
        loop {
            let Some(raw) = self.next_id else {
                return Err(TreeError::NodeIdExhausted);
            };
            let id = NodeId::new(raw);
            self.next_id = raw.checked_add(1);
            if !self.nodes.contains_key(&id) {
                return Ok(id);
            }
        }
    }

    fn advance_allocator_past(&mut self, id: NodeId) {
        if let Some(next) = self.next_id
            && id.get() >= next
        {
            self.next_id = id.get().checked_add(1);
        }
    }

    fn collect_subtree_ids(&self, root: NodeId) -> Result<Vec<NodeId>, TreeError> {
        let mut ids = Vec::new();
        let mut pending = vec![root];
        while let Some(id) = pending.pop() {
            let node = self.nodes.get(&id).ok_or(TreeError::InvariantViolation {
                detail: "child link points to a missing node during removal",
            })?;
            ids.push(id);
            pending.extend(node.children.iter().copied());
        }
        Ok(ids)
    }
}

impl IdentityTree<TestElement> {
    /// Looks up a semantic test element by document-local ID.
    pub fn element(&self, id: NodeId) -> Result<&TestElement, TreeError> {
        self.value(id)
    }

    /// Looks up exact element metadata by document-local ID.
    pub fn metadata(&self, id: NodeId) -> Result<&ElementMetadata, TreeError> {
        Ok(&self.lookup(id)?.value.metadata)
    }

    /// Looks up an element's enabled state by document-local ID.
    pub fn is_enabled(&self, id: NodeId) -> Result<bool, TreeError> {
        Ok(self.lookup(id)?.value.enabled)
    }

    /// Looks up an element's source location by document-local ID.
    pub fn source_location(&self, id: NodeId) -> Result<&SourceLocation, TreeError> {
        Ok(&self.lookup(id)?.value.source_location)
    }

    /// Validates tree structure and every contained element with caller-owned
    /// limits.  The node bound is checked before recursive property accounting
    /// so an oversized direct model is rejected before further work.
    pub fn validate_with_limits(&self, limits: &ValidationLimits) -> Result<(), ModelError> {
        self.validate_bounded(limits)?;
        let mut state = ValidationState::new(limits);
        for node in self.iter_preorder() {
            node.value.validate_into(&mut state)?;
        }
        Ok(())
    }

    /// Compares the semantic tree while excluding each element's runtime and
    /// diagnostic fields.  Node identities, parent links, child order, and
    /// root order remain part of equality because they affect plan topology.
    #[must_use]
    pub fn semantic_eq(&self, other: &Self) -> bool {
        if self.roots != other.roots || self.nodes.len() != other.nodes.len() {
            return false;
        }
        self.nodes.iter().all(|(id, node)| {
            other.nodes.get(id).is_some_and(|candidate| {
                node.parent == candidate.parent
                    && node.children == candidate.children
                    && node.value.semantic_eq(&candidate.value)
            })
        })
    }
}

impl<T> IdentityTree<T>
where
    T: PartialEq,
{
    /// Compares every tree field and value, including runtime/diagnostic
    /// state held by model elements.  This is the explicit structural form of
    /// the derived [`PartialEq`] implementation.
    #[must_use]
    pub fn structural_eq(&self, other: &Self) -> bool {
        self == other
    }
}

impl<T> IdentityTree<T>
where
    T: Clone,
{
    /// Clones the complete tree while retaining document-local IDs and order.
    #[must_use]
    pub fn cloned(&self) -> Self {
        self.clone()
    }
}

/// A semantic tree whose values are TestElements.
pub type ElementTree = IdentityTree<TestElement>;

/// JMeter's insertion-listed child collection.
///
/// `ListedHashTree` intentionally exposes the ordered [`IdentityTree`] API:
/// roots and children retain insertion order, and duplicate-looking values
/// remain separate nodes.  This is the ordering that a JMX boundary must use
/// when serializing a `ListedHashTree`.  The wrapper is distinct from
/// [`HashTree`] so callers cannot accidentally claim that map order is wire
/// order.
#[derive(Clone, PartialEq)]
pub struct ListedHashTree<T = TestElement>(IdentityTree<T>);

impl<T> fmt::Debug for ListedHashTree<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ListedHashTree")
            .field("nodes_len", &self.0.nodes.len())
            .field("roots_len", &self.0.roots.len())
            .finish()
    }
}

impl<T> Default for ListedHashTree<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> ListedHashTree<T> {
    /// Creates an empty insertion-listed tree.
    #[must_use]
    pub const fn new() -> Self {
        Self(IdentityTree::new())
    }

    /// Wraps an existing ordered tree without changing its order.
    #[must_use]
    pub const fn from_tree(tree: IdentityTree<T>) -> Self {
        Self(tree)
    }

    /// Returns the wrapped ordered tree.
    #[must_use]
    pub const fn as_tree(&self) -> &IdentityTree<T> {
        &self.0
    }

    /// Returns mutable access to the wrapped ordered tree.
    pub fn as_tree_mut(&mut self) -> &mut IdentityTree<T> {
        &mut self.0
    }

    /// Consumes the wrapper and returns its ordered tree.
    #[must_use]
    pub fn into_tree(self) -> IdentityTree<T> {
        self.0
    }
}

impl<T> From<IdentityTree<T>> for ListedHashTree<T> {
    fn from(tree: IdentityTree<T>) -> Self {
        Self::from_tree(tree)
    }
}

impl<T> From<ListedHashTree<T>> for IdentityTree<T> {
    fn from(tree: ListedHashTree<T>) -> Self {
        tree.into_tree()
    }
}

impl<T> std::ops::Deref for ListedHashTree<T> {
    type Target = IdentityTree<T>;

    fn deref(&self) -> &Self::Target {
        self.as_tree()
    }
}

impl<T> std::ops::DerefMut for ListedHashTree<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_tree_mut()
    }
}

/// JMeter's identity-keyed hash-tree view.
///
/// Upstream `HashTree` is a keyed map whose duplicate-key operation merges
/// into the existing branch, while `ListedHashTree` is the ordered list used
/// to serialize child elements.  This model uses document-local [`NodeId`]
/// keys rather than hashing arbitrary element values.  [`Self::add_with_id`]
/// is the explicit merge operation: reusing an existing ID under the same
/// parent is idempotent, and reusing it under another parent is a typed error.
/// Hash order is intentionally not an observable semantic; this implementation
/// sorts IDs only to make diagnostics deterministic.
#[derive(Clone, PartialEq)]
pub struct HashTree<T = TestElement>(IdentityTree<T>);

impl<T> fmt::Debug for HashTree<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HashTree")
            .field("nodes_len", &self.0.nodes.len())
            .field("roots_len", &self.0.roots.len())
            .finish()
    }
}

impl<T> Default for HashTree<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> HashTree<T> {
    /// Creates an empty identity-keyed tree.
    #[must_use]
    pub const fn new() -> Self {
        Self(IdentityTree::new())
    }

    /// Wraps an existing tree and normalizes only implementation order.
    #[must_use]
    pub fn from_tree(mut tree: IdentityTree<T>) -> Self {
        Self::normalize(&mut tree);
        Self(tree)
    }

    /// Returns the deterministic backing representation.  Callers must not
    /// treat its sorted order as upstream `HashTree` wire order.
    #[must_use]
    pub const fn as_tree(&self) -> &IdentityTree<T> {
        &self.0
    }

    /// Consumes the wrapper and returns its backing tree.
    #[must_use]
    pub fn into_tree(self) -> IdentityTree<T> {
        self.0
    }

    /// Returns the number of identity keys.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether no identity keys are present.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns roots in deterministic implementation order.  Upstream hash
    /// iteration order remains intentionally unspecified.
    #[must_use]
    pub fn root_ids(&self) -> &[NodeId] {
        self.0.root_ids()
    }

    /// Alias for [`Self::root_ids`].
    #[must_use]
    pub fn roots(&self) -> &[NodeId] {
        self.root_ids()
    }

    /// Returns roots under the identity-keyed view's deterministic order.
    #[must_use]
    pub fn list(&self) -> &[NodeId] {
        self.root_ids()
    }

    /// Returns a deterministic root snapshot.  Callers that need an explicit
    /// allocation guard should use [`Self::get_array_bounded`].  This
    /// convenience is trusted-tree-only.
    #[must_use]
    pub fn get_array(&self) -> Vec<NodeId> {
        self.root_ids().to_vec()
    }

    /// Returns the deterministic root snapshot when it fits a bound.
    pub fn get_array_bounded(&self, max_roots: usize) -> Result<Vec<NodeId>, TreeError> {
        self.0.get_array_bounded(max_roots)
    }

    /// Returns the node for an identity key.
    #[must_use]
    pub fn get(&self, id: NodeId) -> Option<&TreeNode<T>> {
        self.0.get(id)
    }

    /// Returns whether an identity key is present.
    #[must_use]
    pub fn contains(&self, id: NodeId) -> bool {
        self.0.contains(id)
    }

    /// Returns a node for an identity key or a typed missing-key error.
    pub fn lookup(&self, id: NodeId) -> Result<&TreeNode<T>, TreeError> {
        self.0.lookup(id)
    }

    /// Alias for [`Self::lookup`].
    pub fn node(&self, id: NodeId) -> Result<&TreeNode<T>, TreeError> {
        self.lookup(id)
    }

    /// Returns mutable access to a node value.  Structural identity remains
    /// private, so parent/child links cannot be mutated through this method.
    pub fn get_mut(&mut self, id: NodeId) -> Option<&mut TreeNode<T>> {
        self.0.get_mut(id)
    }

    /// Returns mutable access to a node or a typed missing-key error.
    pub fn lookup_mut(&mut self, id: NodeId) -> Result<&mut TreeNode<T>, TreeError> {
        self.0.lookup_mut(id)
    }

    /// Returns a node value.
    pub fn value(&self, id: NodeId) -> Result<&T, TreeError> {
        self.0.value(id)
    }

    /// Returns the parent identity for a key.
    pub fn parent(&self, id: NodeId) -> Result<Option<NodeId>, TreeError> {
        self.0.parent(id)
    }

    /// Returns children in deterministic implementation order.
    pub fn children(&self, id: NodeId) -> Result<&[NodeId], TreeError> {
        self.0.children(id)
    }

    /// Returns whether an identity key has no children.
    pub fn is_leaf(&self, id: NodeId) -> Result<bool, TreeError> {
        self.0.is_leaf(id)
    }

    /// Inserts a fresh key, retaining hash-view normalization.
    pub fn insert(&mut self, parent: Option<NodeId>, value: T) -> Result<NodeId, TreeError> {
        let id = self.0.insert(parent, value)?;
        Self::normalize(&mut self.0);
        Ok(id)
    }

    /// Inserts a fresh root key.
    pub fn insert_root(&mut self, value: T) -> Result<NodeId, TreeError> {
        self.insert(None, value)
    }

    /// Inserts a fresh child key.
    pub fn insert_child(&mut self, parent: NodeId, value: T) -> Result<NodeId, TreeError> {
        self.insert(Some(parent), value)
    }

    /// Inserts a fresh key.
    ///
    /// This legacy name is retained for source compatibility, but it is not
    /// an upstream `HashTree` merge.  Prefer [`Self::insert`] or the explicit
    /// [`Self::add_fresh`] name for fresh insertion, and use
    /// [`Self::add_with_id`] or [`Self::merge_with_id`] when reusing an
    /// upstream identity key.
    #[deprecated(
        note = "HashTree::add is fresh insertion; use insert/add_fresh, or add_with_id/merge_with_id for upstream merge"
    )]
    pub fn add(&mut self, parent: Option<NodeId>, value: T) -> Result<NodeId, TreeError> {
        self.insert(parent, value)
    }

    /// Inserts a fresh key with a name that cannot be confused with merge.
    pub fn add_fresh(&mut self, parent: Option<NodeId>, value: T) -> Result<NodeId, TreeError> {
        self.insert(parent, value)
    }

    /// Inserts a caller-supplied key and rejects any duplicate key.
    pub fn insert_with_id(
        &mut self,
        parent: Option<NodeId>,
        id: NodeId,
        value: T,
    ) -> Result<NodeId, TreeError> {
        let result = self.0.insert_with_id(parent, id, value);
        if result.is_ok() {
            Self::normalize(&mut self.0);
        }
        result
    }

    /// Merges a key into this hash tree.  An existing key under the same
    /// parent is retained unchanged; an existing key under another parent is
    /// rejected instead of silently moving a subtree.
    pub fn add_with_id(
        &mut self,
        parent: Option<NodeId>,
        id: NodeId,
        value: T,
    ) -> Result<NodeId, TreeError> {
        if let Some(existing) = self.0.get(id) {
            if existing.parent() != parent {
                return Err(TreeError::ParentMismatch {
                    id,
                    expected: existing.parent(),
                    actual: parent,
                });
            }
            return Ok(id);
        }
        self.insert_with_id(parent, id, value)
    }

    /// Alias for the explicit hash-key merge operation.
    pub fn merge_with_id(
        &mut self,
        parent: Option<NodeId>,
        id: NodeId,
        value: T,
    ) -> Result<NodeId, TreeError> {
        self.add_with_id(parent, id, value)
    }

    /// Replaces an existing key's value and discards its child subtree.
    pub fn set_with_id(
        &mut self,
        parent: Option<NodeId>,
        id: NodeId,
        value: T,
    ) -> Result<NodeId, TreeError> {
        if let Some(existing) = self.0.get(id) {
            if existing.parent() != parent {
                return Err(TreeError::ParentMismatch {
                    id,
                    expected: existing.parent(),
                    actual: parent,
                });
            }
            self.0.replace_subtree(id, value)?;
            return Ok(id);
        }
        self.insert_with_id(parent, id, value)
    }

    /// Removes a key and all descendants.
    pub fn remove(&mut self, id: NodeId) -> Result<T, TreeError> {
        let value = self.0.remove(id)?;
        Self::normalize(&mut self.0);
        Ok(value)
    }

    /// Removes a leaf key.
    pub fn remove_leaf(&mut self, id: NodeId) -> Result<T, TreeError> {
        let value = self.0.remove_leaf(id)?;
        Self::normalize(&mut self.0);
        Ok(value)
    }

    /// Removes a key and all descendants.
    pub fn remove_subtree(&mut self, id: NodeId) -> Result<T, TreeError> {
        self.remove(id)
    }

    /// Removes all descendants of a key.
    pub fn clear_children(&mut self, id: NodeId) -> Result<usize, TreeError> {
        let count = self.0.clear_children(id)?;
        Self::normalize(&mut self.0);
        Ok(count)
    }

    /// Replaces only a node value while retaining its branch.
    pub fn replace(&mut self, id: NodeId, value: T) -> Result<T, TreeError> {
        self.0.replace(id, value)
    }

    /// Replaces a node value and discards its child branch.
    pub fn replace_subtree(&mut self, id: NodeId, value: T) -> Result<T, TreeError> {
        self.0.replace_subtree(id, value)
    }

    /// Alias for [`Self::replace_subtree`].
    pub fn set(&mut self, id: NodeId, value: T) -> Result<T, TreeError> {
        self.replace_subtree(id, value)
    }

    /// Returns the tree's deterministic preorder iterator.
    #[must_use]
    pub fn iter_preorder(&self) -> PreorderIter<'_, T> {
        self.0.iter_preorder()
    }

    /// Alias for [`Self::iter_preorder`].
    #[must_use]
    pub fn iter(&self) -> PreorderIter<'_, T> {
        self.iter_preorder()
    }

    /// Returns all keys in deterministic preorder when bounded.
    pub fn preorder_ids_bounded(&self, max_nodes: usize) -> Result<Vec<NodeId>, TreeError> {
        self.0.preorder_ids_bounded(max_nodes)
    }

    /// Returns all keys in deterministic preorder.
    ///
    /// This convenience allocates for every node and is trusted-tree-only;
    /// input-facing code should use [`Self::preorder_ids_bounded`].
    #[must_use]
    pub fn preorder_ids(&self) -> Vec<NodeId> {
        self.0.preorder_ids()
    }

    /// Traverses keys in deterministic depth-first order.
    ///
    /// This convenience has no event budget and is trusted-tree-only;
    /// input-facing code should use [`Self::traverse_bounded`].
    pub fn traverse<F>(&self, visitor: F) -> Result<TraversalOutcome, TreeError>
    where
        F: FnMut(VisitEvent) -> TraversalControl,
    {
        self.0.traverse(visitor)
    }

    /// Traverses keys with an event budget.
    pub fn traverse_bounded<F>(
        &self,
        max_events: usize,
        visitor: F,
    ) -> Result<TraversalOutcome, TreeError>
    where
        F: FnMut(VisitEvent) -> TraversalControl,
    {
        self.0.traverse_bounded(max_events, visitor)
    }

    /// Traverses keys while ignoring callback control.
    ///
    /// This convenience has no event budget and is trusted-tree-only;
    /// input-facing code should use [`Self::traverse_bounded`].
    pub fn visit<F>(&self, visitor: F) -> Result<TraversalOutcome, TreeError>
    where
        F: FnMut(VisitEvent),
    {
        self.0.visit(visitor)
    }

    /// Finds the first key satisfying a predicate.
    ///
    /// This convenience has no traversal budget and is trusted-tree-only;
    /// input-facing code should use [`Self::traverse_bounded`] when a
    /// predicate can be evaluated from visit events.
    pub fn find<F>(&self, predicate: F) -> Option<NodeId>
    where
        F: FnMut(&TreeNode<T>) -> bool,
    {
        self.0.find(predicate)
    }

    /// Finds all matching keys in deterministic preorder.
    ///
    /// This convenience allocates for every match and is trusted-tree-only;
    /// input-facing code should use [`Self::find_all_bounded`].
    pub fn find_all<F>(&self, predicate: F) -> Vec<NodeId>
    where
        F: FnMut(&TreeNode<T>) -> bool,
    {
        self.0.find_all(predicate)
    }

    /// Validates structure and node count.
    pub fn validate_bounded(&self, limits: &ValidationLimits) -> Result<(), ModelError> {
        self.0.validate_bounded(limits)
    }

    /// Validates structure without a resource budget.
    ///
    /// This convenience is trusted-tree-only.  Input-facing code should use
    /// [`Self::validate_bounded`] so node count and tree depth are bounded.
    pub fn validate(&self) -> Result<(), TreeError> {
        self.0.validate()
    }

    /// Finds all matching keys under a result bound.
    pub fn find_all_bounded<F>(
        &self,
        max_results: usize,
        predicate: F,
    ) -> Result<Vec<NodeId>, TreeError>
    where
        F: FnMut(&TreeNode<T>) -> bool,
    {
        self.0.find_all_bounded(max_results, predicate)
    }

    /// Returns a root-to-key path under a result bound.
    pub fn path_to_bounded(
        &self,
        id: NodeId,
        max_path_nodes: usize,
    ) -> Result<Vec<NodeId>, TreeError> {
        self.0.path_to_bounded(id, max_path_nodes)
    }

    /// Returns a root-to-key path.
    ///
    /// This convenience has no result budget and is trusted-tree-only;
    /// input-facing code should use [`Self::path_to_bounded`].
    pub fn path_to(&self, id: NodeId) -> Result<Vec<NodeId>, TreeError> {
        self.0.path_to(id)
    }

    /// Returns a key's depth.
    ///
    /// This convenience has no caller-supplied path budget and is
    /// trusted-tree-only; input-facing code should use
    /// [`Self::path_to_bounded`] when a path allocation is required.
    pub fn depth(&self, id: NodeId) -> Result<usize, TreeError> {
        self.0.depth(id)
    }

    /// Returns a cloned hash view retaining its identities.
    #[must_use]
    pub fn cloned(&self) -> Self
    where
        T: Clone,
    {
        self.clone()
    }

    fn normalize(tree: &mut IdentityTree<T>) {
        tree.roots.sort_unstable();
        for node in tree.nodes.values_mut() {
            node.children.sort_unstable();
        }
    }
}

impl<T> From<IdentityTree<T>> for HashTree<T> {
    fn from(tree: IdentityTree<T>) -> Self {
        Self::from_tree(tree)
    }
}

impl<T> From<HashTree<T>> for IdentityTree<T> {
    fn from(tree: HashTree<T>) -> Self {
        tree.into_tree()
    }
}

impl HashTree<TestElement> {
    /// Validates structure, node count, and each contained element.
    pub fn validate_with_limits(&self, limits: &ValidationLimits) -> Result<(), ModelError> {
        self.0.validate_with_limits(limits)
    }

    /// Compares semantic values while retaining hash-key topology.
    #[must_use]
    pub fn semantic_eq(&self, other: &Self) -> bool {
        self.0.semantic_eq(&other.0)
    }
}

/// Short generic tree alias.
pub type Tree<T = TestElement> = IdentityTree<T>;
