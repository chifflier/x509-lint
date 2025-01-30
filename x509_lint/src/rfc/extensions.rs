use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::*;
use x509_parser::prelude::CertificateRevocationList;
use x509_parser::x509::X509Version;

use crate::*;
use crate::{certificate_lint, lint_definition};

pub(crate) const EXTENSION_LINTS: &[(LintDefinition, CertificateLint)] = &[
    (CERT_EXTENSION_NOTV3, cert_extensions_notv3),
    (CERT_EXTENSION_NOTSUPPORTED, cert_extensions_unsuppported),
    (CERT_EXTENSION_PARSEERROR, cert_extensions_parse_error),
    (CERT_EXT_SAN_INVALID_CHARSET, cert_ext_san_invalid_charset),
];

pub(crate) const CRL_EXTENSION_LINTS: &[(LintDefinition, CRLLint)] =
    &[(CRL_EXTENSION_NOTV2, crl_extensions_notv2)];

lint_definition!(
    CERT_EXTENSION_NOTV3,
    "rfc:cert_extensions_notv3",
    "Version is not V3 but extensions are present"
);
certificate_lint!(
    pub(super) cert_extensions_notv3,
    LintStatus::Warn,
    |x509: &X509Certificate| !x509.extensions().is_empty() && x509.version != X509Version::V3
);

lint_definition!(
    CERT_EXTENSION_NOTSUPPORTED,
    "rfc:cert_extensions_unsupported",
    "Unsupported extensions"
);
pub(super) fn cert_extensions_unsuppported(x509: &X509Certificate) -> LintResult {
    for ext in x509.extensions() {
        if let ParsedExtension::UnsupportedExtension { oid } = ext.parsed_extension() {
            let details = LintDetails::new(oid.to_string());
            return LintResult::new_details(LintStatus::Warn, details);
        }
    }
    LintResult::pass()
}

lint_definition!(
    CERT_EXTENSION_PARSEERROR,
    "rfc:cert_extensions_parse_error",
    "Parse error in extension"
);
pub(super) fn cert_extensions_parse_error(x509: &X509Certificate) -> LintResult {
    for ext in x509.extensions() {
        if let ParsedExtension::ParseError { error } = ext.parsed_extension() {
            let details =
                LintDetails::new(format!("Parse error in extension {}: {}", ext.oid, error));
            return LintResult::new_details(LintStatus::Error, details);
        }
    }
    LintResult::pass()
}

lint_definition!(
    CERT_EXT_SAN_INVALID_CHARSET,
    "rfc:cert_ext_san_invalid_charset",
    "Invalid charset in 'SubjectAltName' entry"
);
pub(super) fn cert_ext_san_invalid_charset(x509: &X509Certificate) -> LintResult {
    for ext in x509.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for name in &san.general_names {
                match name {
                    GeneralName::DNSName(s) | GeneralName::RFC822Name(s) => {
                        // should be an ia5string
                        if !s.as_bytes().iter().all(u8::is_ascii) {
                            let details =
                                LintDetails::new(format!("Invalid charset in SAN entry '{}'", s));
                            return LintResult::new_details(LintStatus::Warn, details);
                        }
                    }
                    _ => (),
                }
            }
        }
    }
    LintResult::pass()
}

lint_definition!(
    CRL_EXTENSION_NOTV2,
    "rfc:crl_extensions_notv2",
    "Version is not V2 but extensions are present",
    "RFC5280: 5.1.2.1"
);
crl_lint!(
    pub(super) crl_extensions_notv2,
    LintStatus::Warn,
    |crl: &CertificateRevocationList| !crl.extensions().is_empty() && crl.version() != Some(X509Version::V2)
);
