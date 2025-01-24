use x509_parser::certificate::X509Certificate;
use x509_parser::x509::X509Version;

use super::{CertificateLint, LintDefinition, LintRegistry, LintResult, LintStatus};
use crate::{certificate_lint, lint_definition};

mod extensions;
mod name;

const RFC_LINTS: &[(LintDefinition, CertificateLint)] = &[
    (CHECK_VERSION, check_version),
    (SERIAL_EMPTY, check_serial_empty),
    (SERIAL_MSB, check_serial_msb),
    (SERIAL_LEADING_ZEROES, check_serial_leading_zeroes),
    (CHECK_YEAR_PRE2049_UTC, check_notbefore_utctime_2049),
    (CHECK_YEAR_PRE2049_UTC, check_notafter_utctime_2049),
    (
        CHECK_YEAR_POST2049_UTC,
        check_notbefore_generalizedtime_2049,
    ),
    (CHECK_YEAR_POST2049_UTC, check_notafter_generalizedtime_2049),
    (CHECK_ISSUERID_V1, check_issuer_uniqueid_v1),
    (CHECK_SUBJECTID_V1, check_subject_uniqueid_v1),
];

lint_definition!(CHECK_VERSION, "rfc:check_version", "Invalid X.509 version");
certificate_lint!(
    check_version,
    LintStatus::Error,
    |x509: &X509Certificate| x509.version().0 >= 3
);

lint_definition!(SERIAL_EMPTY, "rfc:serial_empty", "Serial Number is empty");
certificate_lint!(
    check_serial_empty,
    LintStatus::Error,
    |x509: &X509Certificate| x509.raw_serial().is_empty()
);

lint_definition!(
    SERIAL_MSB,
    "rfc:serial_msb",
    "Serial Number is negative",
    "RFC5280: 4.1.2.2"
);
certificate_lint!(
    check_serial_msb,
    LintStatus::Warn,
    |x509: &X509Certificate| {
        let serial = x509.raw_serial();
        !serial.is_empty() && serial[0] & 0x80 != 0
    }
);

lint_definition!(
    SERIAL_LEADING_ZEROES,
    "rfc:serial_leadint_zeroes",
    "Serial Number has leading zeroes"
);
certificate_lint!(
    check_serial_leading_zeroes,
    LintStatus::Warn,
    |x509: &X509Certificate| {
        let b = x509.raw_serial();
        b.len() > 1 && b[0] == 0 && (b[1] & 0x80) == 0
    }
);

lint_definition!(
    CHECK_ISSUERID_V1,
    "rfc:issuer_uniqueid_v1",
    "issuerUniqueID present but version 1"
);
certificate_lint!(
    check_issuer_uniqueid_v1,
    LintStatus::Warn,
    |x509: &X509Certificate| { x509.version() == X509Version::V1 && x509.issuer_uid.is_some() }
);

lint_definition!(
    CHECK_SUBJECTID_V1,
    "rfc:subject_uniqueid_v1",
    "subjectUniqueID present but version 1"
);
certificate_lint!(
    check_subject_uniqueid_v1,
    LintStatus::Warn,
    |x509: &X509Certificate| { x509.version() == X509Version::V1 && x509.subject_uid.is_some() }
);

lint_definition!(
    CHECK_YEAR_PRE2049_UTC,
    "rfc:year_pre2049_utc",
    "certificate validity dates through 2049 MUST be encoded as UTCTime"
);
fn check_notbefore_utctime_2049(x509: &X509Certificate) -> LintResult {
    let validity = x509.validity();
    let year_notbefore = validity.not_before.to_datetime().year();
    if year_notbefore <= 2049 && !validity.not_before.is_utctime() {
        LintResult::new_details(LintStatus::Warn, "notBefore".into())
    } else {
        LintResult::pass()
    }
}
fn check_notafter_utctime_2049(x509: &X509Certificate) -> LintResult {
    let validity = x509.validity();
    let year_notafter = validity.not_after.to_datetime().year();
    if year_notafter <= 2049 && !validity.not_after.is_utctime() {
        LintResult::new_details(LintStatus::Warn, "notAfter".into())
    } else {
        LintResult::pass()
    }
}

lint_definition!(
    CHECK_YEAR_POST2049_UTC,
    "rfc:year_post2049_utc",
    "certificate validity dates in 2050 or later MUST be encoded as GeneralizedTime"
);
fn check_notbefore_generalizedtime_2049(x509: &X509Certificate) -> LintResult {
    let validity = x509.validity();
    let year_notbefore = validity.not_before.to_datetime().year();
    if year_notbefore > 2049 && validity.not_before.is_utctime() {
        LintResult::new_details(LintStatus::Warn, "notBefore".into())
    } else {
        LintResult::pass()
    }
}
fn check_notafter_generalizedtime_2049(x509: &X509Certificate) -> LintResult {
    let validity = x509.validity();
    let year_notafter = validity.not_after.to_datetime().year();
    if year_notafter > 2049 && validity.not_after.is_utctime() {
        LintResult::new_details(LintStatus::Warn, "notAfter".into())
    } else {
        LintResult::pass()
    }
}

/// Return a [`LintRegistry`] containing all RFC lints included in this crate
pub fn rfc_lints<'a>() -> LintRegistry<'a> {
    let all_rfc_lints = [RFC_LINTS, name::NAME_LINTS, extensions::EXTENSION_LINTS].concat();
    LintRegistry::new(all_rfc_lints)
}

#[cfg(test)]
mod tests {
    use x509_parser::prelude::FromDer;

    use super::*;

    #[test]
    fn lints_rfc() {
        let mut path_ca1 = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path_ca1.push("assets/IGC_A.der");
        let data = std::fs::read(path_ca1).expect("DER file not found");
        let (_, x509) = X509Certificate::from_der(&data).expect("Could not parse certificate");

        let registry = rfc_lints();
        {
            let res = registry.run_lints(&x509);
            dbg!(&res);
        }
    }
}
