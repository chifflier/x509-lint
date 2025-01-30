/// Definition of a Lint: name, description, citation (optional)
#[derive(Debug, Clone)]
pub struct LintDefinition<'a> {
    /// Lint name (identifier). Must be unique
    pub(crate) name: &'a str,
    /// Lint description
    pub(crate) description: &'a str,
    /// Lint citation (precise reference), for ex "RFC5280: 4.2.1.1"
    pub(crate) citation: Option<&'a str>,
}

impl<'a> LintDefinition<'a> {
    /// Build a new lint definition from arguments
    #[inline]
    pub const fn new(name: &'a str, description: &'a str) -> Self {
        Self {
            name,
            description,
            citation: None,
        }
    }

    /// Lint name (identifier). Must be unique
    #[inline]
    pub const fn name(&self) -> &str {
        self.name
    }

    /// Lint description
    #[inline]
    pub const fn description(&self) -> &str {
        self.description
    }

    /// Lint citation (precise reference), for ex "RFC5280: 4.2.1.1"
    #[inline]
    pub const fn citation(&self) -> Option<&str> {
        self.citation
    }

    /// Add `citation` to the current definition
    #[inline]
    pub const fn with_citation(self, citation: &'a str) -> Self {
        Self {
            citation: Some(citation),
            ..self
        }
    }
}

/// Helper macro to define a new lint
///
/// # Example
///
/// ```rust
/// use x509_lint::*;
///
/// lint_definition!(
///     CHECK_VERSION /* definition name */,
///     "rfc:check_version" /* lint name (must be unique) */,
///     "Invalid X.509 version" /* lint description */,
///     "RFC5280: 4.1.2.1" /* lint citation (optional) */);
/// ``````
#[macro_export]
macro_rules! lint_definition {
    ($vis:vis $lint_def:ident, $lint_name:expr, $lint_description:expr) => {
        $vis const $lint_def: $crate::LintDefinition =
            $crate::LintDefinition::new($lint_name, $lint_description);
    };
    ($vis:vis $lint_def:ident, $lint_name:expr, $lint_description:expr, $citation:expr) => {
        $vis const $lint_def: $crate::LintDefinition =
            $crate::LintDefinition::new($lint_name, $lint_description).with_citation($citation);
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    // test definition
    const _DEF1: LintDefinition = LintDefinition::new("name", "description");

    lint_definition!(_DEF2, "name", "description");

    lint_definition!(_DEF3, "name", "description", "citation");
}
