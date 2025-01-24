use x509_parser::asn1_rs::Tag;
use x509_parser::prelude::X509Certificate;

use crate::*;

pub(crate) const NAME_LINTS: &[(LintDefinition, CertificateLint)] = &[
    (
        SUBJECT_CN_NOT_PRINTABLESTRING,
        subject_cn_not_printablestring,
    ),
    (ISSUER_EMPTY, issuer_empty),
];

lint_definition!(
    SUBJECT_CN_NOT_PRINTABLESTRING,
    "rfc:subject_countryname_not_printablestring",
    "Subject DN: CountryName MUST be encoded as PrintableString",
    "RFC5280: Appendix A"
);
pub(super) fn subject_cn_not_printablestring(x509: &X509Certificate) -> LintResult {
    let subject = x509.subject();
    for attr in subject.iter_country() {
        if attr.attr_value().tag() != Tag::PrintableString {
            return LintResult::new(LintStatus::Error);
        }
    }
    LintResult::pass()
}

lint_definition!(
    ISSUER_EMPTY,
    "rfc:issuer_empty",
    "The issuer field MUST contain a non-empty distinguished name (DN)",
    "RFC5280: 4.1.2.4"
);
pub(super) fn issuer_empty(x509: &X509Certificate) -> LintResult {
    let issuer = x509.issuer();

    if issuer.iter().count() == 0 {
        return LintResult::new(LintStatus::Error);
    }

    LintResult::pass()
}
