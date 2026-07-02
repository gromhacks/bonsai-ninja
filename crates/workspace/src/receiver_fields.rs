//! Language-neutral receiver-field shape helpers.
//!
//! These helpers are deliberately conservative: they identify writes to
//! the current receiver (`self`, `this`, `$this`, Ruby instance vars),
//! not arbitrary member writes on local objects.

/// True when `target` is syntactically a write to current receiver
/// state.
///
/// Accepted shapes include `self.x`, `this.x`, `this->x`,
/// `$this->x`, and Ruby instance variables such as `@x`. Generic
/// member writes like `holder.x` are rejected; without alias evidence
/// they are object-field writes, not class-state writes.
#[must_use]
pub fn receiver_field_target(target: &str) -> bool {
    let target = target.trim();
    if target.is_empty() {
        return false;
    }
    if bonsai_common::IMPLICIT_RECEIVER_PREFIXES
        .iter()
        .any(|prefix| target.starts_with(*prefix))
    {
        return true;
    }
    if bonsai_common::IMPLICIT_RECEIVER_TOKENS
        .iter()
        .any(|token| target.starts_with(&format!("{token}->")))
    {
        return true;
    }
    if let Some(rest) = target.strip_prefix('$') {
        if bonsai_common::IMPLICIT_RECEIVER_TOKENS
            .iter()
            .any(|token| rest.starts_with(&format!("{token}->")))
        {
            return true;
        }
    }
    target.starts_with('@')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_explicit_receiver_field_shapes() {
        for target in [
            "self.value",
            "this.value",
            "this->value",
            "$this->value",
            "@value",
        ] {
            assert!(receiver_field_target(target), "{target}");
        }
    }

    #[test]
    fn rejects_generic_member_writes_without_receiver_evidence() {
        for target in [
            "holder.value",
            "request->value",
            "pkg::value",
            "$value",
            "value",
            "",
        ] {
            assert!(!receiver_field_target(target), "{target}");
        }
    }
}
