use std::fmt;

/// Lint check status
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum LintStatus {
    /// Lint verification success
    Pass = 0,
    /// Lint warning
    Warn = 4,
    /// Lint error
    Error = 5,
}

impl fmt::Display for LintStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match *self {
            LintStatus::Pass => "pass",
            LintStatus::Warn => "warn",
            LintStatus::Error => "error",
        };
        f.write_str(s)
    }
}
