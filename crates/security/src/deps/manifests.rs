//! Exact package-bearing projections from data manifests. Syntax is parsed by
//! its data-format frontend; the rulepack owns filenames and field roles.

use super::{dependency_manifest_pattern_matches, insert_dependency_package_token};
use crate::loader::{DependencyManifestFormat, DependencyManifestLayout, DependencyPackageSelector};
use ahash::AHashSet;
use bonsai_workspace::Workspace;
use serde_json::Value;
use std::path::Path;

mod code;

#[derive(Debug, thiserror::Error)]
#[error("unsupported dependency manifest format")]
pub(super) struct UnsupportedManifest;

pub(super) fn packages(
    path: &Path,
    text: &str,
    layouts: &[DependencyManifestLayout],
    ws: Option<&Workspace>,
) -> anyhow::Result<AHashSet<String>> {
    let basename = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    let matching: Vec<_> = layouts
        .iter()
        .filter(|layout| {
            layout
                .files
                .iter()
                .any(|pattern| dependency_manifest_pattern_matches(pattern, basename))
        })
        .collect();
    if matching.is_empty() {
        return Err(UnsupportedManifest.into());
    }
    let mut output = AHashSet::new();
    for layout in matching {
        layout.validate()?;
        if layout.format == DependencyManifestFormat::Code {
            code::project(path, text, layout, ws, &mut output)?;
        } else {
            project(text, layout, &mut output)?;
        }
    }
    Ok(output)
}

fn project(
    text: &str,
    layout: &DependencyManifestLayout,
    output: &mut AHashSet<String>,
) -> anyhow::Result<()> {
    if layout.format == DependencyManifestFormat::Lines {
        for selector in &layout.packages {
            let capture = regex::Regex::new(
                selector
                    .capture
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("line-record selector requires a capture"))?,
            )?;
            for line in text.lines() {
                admit(line, Some(&capture), output);
            }
        }
        return Ok(());
    }
    if layout.format == DependencyManifestFormat::Xml {
        let document = roxmltree::Document::parse(text)?;
        for selector in &layout.packages {
            let capture = selector.capture.as_deref().map(regex::Regex::new).transpose()?;
            let (path, attribute) = selector
                .path
                .last()
                .and_then(|last| last.strip_prefix('@'))
                .map_or((selector.path.as_slice(), None), |attribute| {
                    (&selector.path[..selector.path.len() - 1], Some(attribute))
                });
            let mut nodes = vec![document.root()];
            for component in path {
                nodes = nodes
                    .into_iter()
                    .flat_map(|node| {
                        node.children().filter(move |child| {
                            child.is_element() && (component == "*" || child.tag_name().name() == component)
                        })
                    })
                    .collect();
            }
            for node in nodes {
                let value = attribute.map_or_else(|| node.text(), |name| node.attribute(name));
                if let Some(value) = value {
                    admit(value, capture.as_ref(), output);
                }
            }
        }
        return Ok(());
    }
    let document: Value = match layout.format {
        DependencyManifestFormat::Json => serde_json::from_str(text)?,
        DependencyManifestFormat::Yaml => serde_yaml::from_str(text)?,
        DependencyManifestFormat::Toml => serde_json::to_value(toml::from_str::<toml::Value>(text)?)?,
        DependencyManifestFormat::Xml | DependencyManifestFormat::Lines | DependencyManifestFormat::Code => {
            unreachable!("non-value documents handled above")
        }
    };
    for selector in &layout.packages {
        let capture = selector.capture.as_deref().map(regex::Regex::new).transpose()?;
        let mut nodes = vec![&document];
        for component in &selector.path {
            nodes = nodes
                .into_iter()
                .flat_map(|node| child_values(node, component))
                .collect();
        }
        for node in nodes {
            project_selector(node, selector, capture.as_ref(), output);
        }
    }
    Ok(())
}

fn child_values<'a>(node: &'a Value, component: &str) -> Vec<&'a Value> {
    match node {
        Value::Object(map) if component == "*" => map.values().collect(),
        Value::Object(map) => map.get(component).into_iter().collect(),
        Value::Array(items) if component == "*" => items.iter().collect(),
        _ => Vec::new(),
    }
}

fn project_selector(
    node: &Value,
    selector: &DependencyPackageSelector,
    capture: Option<&regex::Regex>,
    output: &mut AHashSet<String>,
) {
    let mut pending = vec![node];
    while let Some(node) = pending.pop() {
        if selector.keys {
            if let Some(map) = node.as_object() {
                for (key, value) in map {
                    admit(key, capture, output);
                    if let Some(nested) = &selector.nested {
                        pending.extend(value.get(nested));
                    }
                }
            }
        } else if let Some(value) = node.as_str() {
            admit(value, capture, output);
        }
    }
}

fn admit(value: &str, capture: Option<&regex::Regex>, output: &mut AHashSet<String>) {
    if let Some(capture) = capture {
        if let Some(matched) = capture.captures(value).and_then(|captures| captures.get(1)) {
            insert_dependency_package_token(output, matched.as_str());
        }
    } else {
        insert_dependency_package_token(output, value.trim());
    }
}
