//! Objective-C method-family identity from the method signature and attributes.
//! C functions with similar names are unrelated. See Clang's ARC method-family
//! contract: https://clang.llvm.org/docs/AutomaticReferenceCounting.html#method-families

use bonsai_lang_api::{kit::node_text, DeclIndex, DeclKind};
use tree_sitter::{Node, Tree};

pub(super) fn initializer_selectors(index: &DeclIndex) -> std::collections::HashMap<(String, String), bool> {
    let owners = index
        .defs
        .iter()
        .filter(|decl| decl.kind == DeclKind::Class)
        .map(|decl| (decl.symbol, decl.name.as_str()))
        .collect::<std::collections::HashMap<_, _>>();
    let mut result = std::collections::HashMap::new();
    for decl in &index.defs {
        if !matches!(decl.kind, DeclKind::Method | DeclKind::Constructor) {
            continue;
        }
        let Some(owner) = decl.parent.and_then(|parent| owners.get(&parent)) else {
            continue;
        };
        let selector = decl
            .qualified_name
            .as_deref()
            .and_then(|name| bonsai_common::declaration_qualified_suffix(&decl.name, name))
            .unwrap_or(&decl.name);
        let initializer = decl.kind == DeclKind::Constructor;
        result
            .entry(((*owner).to_string(), selector.to_string()))
            .and_modify(|known| *known &= initializer)
            .or_insert(initializer);
    }
    result
}

pub(super) fn mark_initializers(index: &mut DeclIndex, tree: &Tree, source: &[u8]) {
    let classes = index
        .defs
        .iter()
        .filter(|decl| decl.kind == DeclKind::Class)
        .map(|decl| decl.name.as_str())
        .collect::<std::collections::HashSet<_>>();
    // Compute before mutating declarations: class names borrow this exact index.
    let initializers = index
        .defs
        .iter()
        .map(|decl| {
            if decl.kind != DeclKind::Method {
                return false;
            }
            let Some(mut node) = tree
                .root_node()
                .named_descendant_for_byte_range(decl.name_span.start as usize, decl.name_span.end as usize)
            else {
                return false;
            };
            while !matches!(node.kind(), "method_declaration" | "method_definition") {
                let Some(parent) = node.parent() else {
                    return false;
                };
                node = parent;
            }
            let mut cursor = node.walk();
            if !node.children(&mut cursor).any(|child| child.kind() == "-") {
                return false;
            }
            let mut cursor = node.walk();
            let Some(return_type) = node
                .named_children(&mut cursor)
                .find(|child| child.kind() == "method_type")
            else {
                return false;
            };
            if !is_object_return(return_type, source, &classes) {
                return false;
            }
            explicit_family(node, source).map_or_else(
                || super::objc_selector_is_initializer(&decl.name),
                |family| family == "init",
            )
        })
        .collect::<Vec<_>>();
    for (decl, initializer) in index.defs.iter_mut().zip(initializers) {
        if initializer {
            decl.kind = DeclKind::Constructor;
        }
    }
}

fn is_object_return(node: Node<'_>, source: &[u8], classes: &std::collections::HashSet<&str>) -> bool {
    let mut pending = vec![node];
    let mut base = None;
    let mut pointers = 0;
    while let Some(node) = pending.pop() {
        match node.kind() {
            "typedefed_specifier" | "type_identifier" | "primitive_type" => {
                if base.replace(node_text(&node, source)).is_some() {
                    return false;
                }
            }
            "*" => pointers += 1,
            "parameterized_arguments" | "protocol_reference_list" | "type_qualifier" => {}
            "abstract_function_declarator" | "abstract_array_declarator" | "block_pointer_declarator" => {
                return false
            }
            _ => {
                let mut cursor = node.walk();
                pending.extend(node.children(&mut cursor));
            }
        }
    }
    base.is_some_and(|base| {
        (matches!(base, "id" | "instancetype" | "Class") && pointers == 0)
            || (classes.contains(base) && pointers == 1)
    })
}

fn explicit_family<'a>(node: Node<'_>, source: &'a [u8]) -> Option<&'a str> {
    // Only declaration attributes, never calls in the implementation body or
    // attributes nested inside a parameter's type.
    let mut pending = vec![node];
    while let Some(current) = pending.pop() {
        if current.kind() == "attribute_specifier" {
            let mut attributes = vec![current];
            while let Some(attribute) = attributes.pop() {
                if attribute.kind() == "call_expression" {
                    if let Some(function) = attribute.child_by_field_name("function") {
                        if node_text(&function, source) == "objc_method_family" {
                            let arguments = attribute.child_by_field_name("arguments")?;
                            if arguments.named_child_count() != 1 {
                                return Some("");
                            }
                            return Some(node_text(&arguments.named_child(0)?, source));
                        }
                    }
                }
                let mut cursor = attribute.walk();
                attributes.extend(attribute.named_children(&mut cursor));
            }
        } else if current == node || current.kind() == "method_parameter" {
            let mut cursor = current.walk();
            pending.extend(current.named_children(&mut cursor));
        }
    }
    None
}
