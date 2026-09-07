//! Fallible filters over adapter-proven lexical facts.

/// A literal inventory filter could not be evaluated exactly.
#[derive(Debug)]
pub enum LiteralFilterError {
    /// The caller supplied an invalid regular expression.
    Regex(regex::Error),
    /// The adapter did not prove the lexical body length at this location.
    UnknownContentLength { file: String, line: u32, column: u32 },
}

impl std::fmt::Display for LiteralFilterError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Regex(error) => write!(formatter, "{error}"),
            Self::UnknownContentLength { file, line, column } => write!(
                formatter,
                "cannot apply --min-len: adapter did not prove the lexical body length at {file}:{line}:{column}; omit --min-len to retain this fact"
            ),
        }
    }
}

impl std::error::Error for LiteralFilterError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Regex(error) => Some(error),
            Self::UnknownContentLength { .. } => None,
        }
    }
}

impl From<regex::Error> for LiteralFilterError {
    fn from(error: regex::Error) -> Self {
        Self::Regex(error)
    }
}

pub(crate) fn matches_min_len(
    content_len: Option<usize>,
    minimum: Option<usize>,
    location: impl FnOnce() -> (String, u32, u32),
) -> Result<bool, LiteralFilterError> {
    let Some(minimum) = minimum.filter(|minimum| *minimum > 0) else {
        return Ok(true);
    };
    if let Some(length) = content_len {
        return Ok(length >= minimum);
    }
    let (file, line, column) = location();
    Err(LiteralFilterError::UnknownContentLength { file, line, column })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_length_is_not_silently_guessed_or_filtered_out() {
        for minimum in [None, Some(0)] {
            assert!(matches_min_len(None, minimum, || unreachable!()).unwrap());
        }
        let error = matches_min_len(None, Some(1), || ("app.ext".into(), 3, 4)).unwrap_err();
        assert!(matches!(error, LiteralFilterError::UnknownContentLength { .. }));
        assert!(error.to_string().contains("app.ext:3:4"));
        assert!(!matches_min_len(Some(0), Some(1), || unreachable!()).unwrap());
        assert!(matches_min_len(Some(4), Some(4), || unreachable!()).unwrap());
    }
}
