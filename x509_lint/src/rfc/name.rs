use x509_parser::asn1_rs::Tag;
use x509_parser::prelude::X509Certificate;

use crate::*;

pub(crate) const NAME_LINTS: &[(LintDefinition, CertificateLint)] = &[(
    SUBJECT_CN_NOT_PRINTABLESTRING,
    subject_cn_not_printablestring,
)];

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
