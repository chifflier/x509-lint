//! X.509 Certificate and CRL linter
//!
//! This crate provides two kinds of lints: [`CertificateLint`] for X.509 Certificates,
//! and [`CRLLint`] for X.509 Certificate Revocation Lists.
//!
//! Lints are simple functions receiving a parsed object, and returning a [`LintResult`].
//!
//! # Running lints
//!
//! To run lints, either define and call the lints directly, or use a lint registry to
//! store lint definitions and functions.
//!
//! This crate provides default registries for certificates and CRLs.
//!
//! For example, to get the default registry for RFC5280 lints on X.509 Certificates,
//! use the following:
//!
//! ```rust
//! use x509_lint::*;
//! use x509_lint::x509_parser::prelude::X509Certificate;
//!
//! fn check_certificate(x509: &X509Certificate<'_>) {
//!     let registry = rfc_lints();
//!     let _results = registry.run_lints(x509);
//!     // use results
//! }
//! ```
//!
//! `run_lints` returns a list of [`LintDefinition`] and [`LintResult`].
//! The lifetime of definitions is the lifetime of the registry containing them.
//!
//! Similarly, [`crl_rfc_lints`] returns a registry for CRL lints.
//!
//! # Adding lints
//!
//! To add a new lint to a registry, a [`LintDefinition`] and a function are required.
//! Helpers macros [`certificate_lint`] and [`crl_lint`] are provided to simplify declaration.
//!
//! Example:
//!
//! ```rust
//! use x509_lint::*;
//! use x509_lint::x509_parser::prelude::X509Certificate;
//!
//! lint_definition!(
//!     CHECK_VERSION /* definition name */,
//!     "rfc:check_version" /* lint name (must be unique) */,
//!     "Invalid X.509 version" /* lint description */,
//!     "RFC5280: 4.1.2.1" /* lint citation (optional) */);
//!
//! fn test_certificate_version(x509: &X509Certificate<'_>) -> LintResult {
//!     if x509.version.0 >= 3 {
//!         LintResult::new(LintStatus::Error)
//!     } else {
//!         LintResult::pass()
//!     }
//! }
//!
//! // adding to a registry
//! let mut registry = CertificateLintRegistry::default();
//! registry.insert(CHECK_VERSION, test_certificate_version);
//! ```
//!
//! The `LintResult` can also provide some details (see [`LintDetails`]):
//! ```rust
//! # use x509_lint::*;
//! # use x509_lint::x509_parser::prelude::X509Certificate;
//! # fn test_certificate_version(x509: &X509Certificate<'_>) -> LintResult {
//! if x509.version.0 >= 3 {
//!     let details = LintDetails::from("details on lint error");
//!     LintResult::new(LintStatus::Error).with_details(details)
//! } else {
//!     LintResult::pass()
//! }
//! # }
//! ```

#![deny(/*missing_docs,*/
    unstable_features,
    unused_import_braces, unused_qualifications)]
#![warn(
    missing_debug_implementations,
    missing_docs,
 /* rust_2018_idioms,*/
unreachable_pub
)]
#![forbid(unsafe_code)]
#![deny(rustdoc::broken_intra_doc_links)]
#![doc(test(
    no_crate_inject,
    attr(deny(warnings, rust_2018_idioms), allow(dead_code, unused_variables))
))]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod certificate_lint;
mod crl_lint;
mod definition;
mod registry;
mod result;
mod rfc;
mod status;

pub use certificate_lint::*;
pub use crl_lint::*;
pub use definition::*;
pub use registry::*;
pub use result::*;
pub use rfc::*;
pub use status::*;

// re-exports
pub use x509_parser;
