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
