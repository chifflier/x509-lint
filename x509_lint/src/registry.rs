use x509_parser::{certificate::X509Certificate, prelude::CertificateRevocationList};

use super::*;

/// Registry containing X.509 Certificate lint functions
#[allow(missing_debug_implementations)]
#[derive(Default)]
pub struct CertificateLintRegistry<'a> {
    lints: Vec<(LintDefinition<'a>, CertificateLint)>,
}

impl<'a> CertificateLintRegistry<'a> {
    /// Build a new registry from provided lint definitions and functions
    pub fn new(lints: Vec<(LintDefinition<'a>, CertificateLint)>) -> Self {
        Self { lints }
    }

    /// Return a iterator on the registered lint definitions and functions
    pub fn lints(&self) -> impl Iterator<Item = &(LintDefinition, CertificateLint)> {
        self.lints.iter()
    }

    /// Register a new lint definition and function
    pub fn insert(&mut self, lint_definition: LintDefinition<'a>, lint: CertificateLint) {
        self.lints.push((lint_definition, lint));
    }

    /// Merge lints from registry `other` in the current registry
    pub fn merge(&mut self, mut other: CertificateLintRegistry<'a>) {
        self.lints.append(&mut other.lints);
    }

    /// Filter lints, keeping only lints with name matching the provided filter
    ///
    /// Currently, the matching function is `starts_with`, and only one filter can be provided
    pub fn filter(&mut self, filter: &str) {
        self.lints.retain(|(def, _)| def.name.starts_with(filter));
    }

    /// Run lint functions on the certificate, returning only the results of lints not returning `Pass`
    pub fn run_lints(
        &'a self,
        x509: &X509Certificate,
    ) -> Vec<(&'a LintDefinition<'a>, LintResult)> {
        self.lints
            .iter()
            .filter_map(|(lint_definition, lint)| {
                let r = (*lint)(x509);
                match r.status {
                    LintStatus::Pass => None,
                    _ => Some((lint_definition, r)),
                }
            })
            .collect()
    }
}

impl<'a> FromIterator<(LintDefinition<'a>, CertificateLint)> for CertificateLintRegistry<'a> {
    fn from_iter<T: IntoIterator<Item = (LintDefinition<'a>, CertificateLint)>>(iter: T) -> Self {
        let v = iter.into_iter().collect();
        Self::new(v)
    }
}

/// Registry containing X.509 Certificate Revocation List lint functions
#[allow(missing_debug_implementations)]
#[derive(Default)]
pub struct CRLLintRegistry<'a> {
    lints: Vec<(LintDefinition<'a>, CRLLint)>,
}

impl<'a> CRLLintRegistry<'a> {
    /// Build a new registry from provided lint definitions and functions
    pub fn new(lints: Vec<(LintDefinition<'a>, CRLLint)>) -> Self {
        Self { lints }
    }

    /// Return a iterator on the registered lint definitions and functions
    pub fn lints(&self) -> impl Iterator<Item = &(LintDefinition, CRLLint)> {
        self.lints.iter()
    }

    /// Register a new lint definition and function
    pub fn insert(&mut self, lint_definition: LintDefinition<'a>, lint: CRLLint) {
        self.lints.push((lint_definition, lint));
    }

    /// Merge lints from registry `other` in the current registry
    pub fn merge(&mut self, mut other: CRLLintRegistry<'a>) {
        self.lints.append(&mut other.lints);
    }

    /// Filter lints, keeping only lints with name matching the provided filter
    ///
    /// Currently, the matching function is `starts_with`, and only one filter can be provided
    pub fn filter(&mut self, filter: &str) {
        self.lints.retain(|(def, _)| def.name.starts_with(filter));
    }

    /// Run lint functions on the CRL, returning only the results of lints not returning `Pass`
    pub fn run_lints(
        &'a self,
        crl: &CertificateRevocationList,
    ) -> Vec<(&'a LintDefinition<'a>, LintResult)> {
        self.lints
            .iter()
            .filter_map(|(lint_definition, lint)| {
                let r = (*lint)(crl);
                match r.status {
                    LintStatus::Pass => None,
                    _ => Some((lint_definition, r)),
                }
            })
            .collect()
    }
}

impl<'a> FromIterator<(LintDefinition<'a>, CRLLint)> for CRLLintRegistry<'a> {
    fn from_iter<T: IntoIterator<Item = (LintDefinition<'a>, CRLLint)>>(iter: T) -> Self {
        let v = iter.into_iter().collect();
        Self::new(v)
    }
}
