use core::fmt;

use super::LintStatus;

/// Lint check result
#[derive(Debug)]
pub struct LintResult {
    /// Lint status: pass, fail, etc.
    pub status: LintStatus,
    /// Lint details (optional)
    pub details: Option<LintDetails>,
}

impl LintResult {
    /// Build a new lint result (without details)
    #[inline]
    pub const fn new(status: LintStatus) -> Self {
        Self {
            status,
            details: None,
        }
    }

    /// Build a new lint result (with details)
    #[inline]
    pub const fn new_details(status: LintStatus, details: LintDetails) -> Self {
        Self {
            status,

            details: Some(details),
        }
    }

    /// Build a new lint result (PASS, without details)
    #[inline]
    pub const fn pass() -> Self {
        Self {
            status: LintStatus::Pass,

            details: None,
        }
    }

    /// Update the lint result and add details
    pub fn with_details(self, details: LintDetails) -> Self {
        Self {
            details: Some(details),
            ..self
        }
    }
}

/// Lint result details (text additional information)
///
/// Note: this is an opaque structure, implementation may change in the future
/// (type could perhaps be replaced by a plain `String`).
#[derive(Debug)]
pub struct LintDetails {
    value: String,
}

impl LintDetails {
    /// Build details from string
    pub fn new(value: String) -> Self {
        Self { value }
    }
}

impl fmt::Display for LintDetails {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.value)
    }
}

impl From<&str> for LintDetails {
    fn from(value: &str) -> Self {
        LintDetails::new(value.to_string())
    }
}
