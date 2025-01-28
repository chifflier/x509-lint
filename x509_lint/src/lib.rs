//! X.509 Certificate and CRL linter

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
mod definition;
mod registry;
mod result;
mod rfc;
mod status;

pub use certificate_lint::*;
pub use definition::*;
pub use registry::*;
pub use result::*;
pub use rfc::*;
pub use status::*;

// re-exports
pub use x509_parser;
