use std::path::{Path, PathBuf};

pub struct InputValidator {
    max_length: usize,
    allowed_chars: Vec<char>,
}

impl InputValidator {
    pub fn new(max_length: usize) -> Self {
        InputValidator {
            max_length,
            allowed_chars: Vec::new(),
        }
    }

    pub fn with_allowed_chars(mut self, chars: &[char]) -> Self {
        self.allowed_chars = chars.to_vec();
        self
    }

    pub fn validate(&self, input: &str) -> Result<&str, String> {
        if input.len() > self.max_length {
            return Err("Input too long".into());
        }
        if !self.allowed_chars.is_empty() {
            for c in input.chars() {
                if !self.allowed_chars.contains(&c) {
                    return Err(format!("Invalid character: {}", c));
                }
            }
        }
        Ok(input)
    }

    pub fn sanitize(&self, input: &str) -> String {
        let mut result = String::new();
        for c in input.chars() {
            if self.allowed_chars.is_empty() || self.allowed_chars.contains(&c) {
                result.push(c);
            }
        }
        if result.len() > self.max_length {
            result.truncate(self.max_length);
        }
        result
    }
}

pub struct PathSanitizer {
    base_dir: PathBuf,
}

impl PathSanitizer {
    pub fn new(base_dir: &str) -> Self {
        PathSanitizer {
            base_dir: PathBuf::from(base_dir),
        }
    }

    pub fn sanitize(&self, filename: &str) -> Result<PathBuf, String> {
        let clean_name = Path::new(filename)
            .file_name()
            .ok_or("Invalid filename")?
            .to_str()
            .ok_or("Invalid UTF-8")?;
        let full_path = self.base_dir.join(clean_name);
        let canonical = full_path.canonicalize().map_err(|e| e.to_string())?;
        let base_canonical = self.base_dir.canonicalize().map_err(|e| e.to_string())?;
        if !canonical.starts_with(&base_canonical) {
            return Err("Path traversal detected".into());
        }
        Ok(canonical)
    }
}

pub struct HtmlEscaper;

impl HtmlEscaper {
    pub fn escape(input: &str) -> String {
        let mut result = String::with_capacity(input.len());
        for c in input.chars() {
            match c {
                '&' => result.push_str("&amp;"),
                '<' => result.push_str("&lt;"),
                '>' => result.push_str("&gt;"),
                '"' => result.push_str("&quot;"),
                '\'' => result.push_str("&#x27;"),
                _ => result.push(c),
            }
        }
        result
    }
}

pub struct SqlSanitizer;

impl SqlSanitizer {
    pub fn escape_string(input: &str) -> String {
        input.replace('\'', "''").replace('\\', "\\\\")
    }

    pub fn is_valid_identifier(input: &str) -> bool {
        input.chars().all(|c| c.is_alphanumeric() || c == '_')
    }
}

pub struct UrlValidator {
    allowed_schemes: Vec<String>,
    blocked_hosts: Vec<String>,
}

impl UrlValidator {
    pub fn new() -> Self {
        UrlValidator {
            allowed_schemes: vec!["http".into(), "https".into()],
            blocked_hosts: vec![
                "localhost".into(),
                "127.0.0.1".into(),
                "0.0.0.0".into(),
                "169.254.169.254".into(),
            ],
        }
    }

    pub fn validate(&self, url: &str) -> Result<(), String> {
        let has_valid_scheme = self.allowed_schemes.iter().any(|s| url.starts_with(&format!("{}://", s)));
        if !has_valid_scheme {
            return Err("Invalid URL scheme".into());
        }
        for host in &self.blocked_hosts {
            if url.contains(host) {
                return Err(format!("Blocked host: {}", host));
            }
        }
        Ok(())
    }
}
