use x509_parser::prelude::CertificateRevocationList;

use super::*;

/// Prototype for X.509 certificate lint function
pub type CRLLint = fn(_crl: &CertificateRevocationList) -> LintResult;

/// Helper macro to define a new lint
///
/// If $link_fn returns true, emit lint warning
#[macro_export]
macro_rules! crl_lint {
    ($vis:vis $lint_fn:ident, $lvl:expr, $lint:expr) => {
        #[allow(unused_qualifications)]
        $vis fn $lint_fn(crl: &x509_parser::revocation_list::CertificateRevocationList) -> LintResult {
            let f = $lint;
            if f(crl) {
                // eprintln!("lint fail: {}", $lint_name);
                $crate::LintResult::new($lvl)
            } else {
                $crate::LintResult::pass()
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    // test macro for certificate lint definition
    crl_lint!(
        test_lint1,
        LintStatus::Error,
        |crl: &CertificateRevocationList| crl.version.0 >= 3
    );

    #[test]
    fn test_cert_macro() {
        let _ = test_lint1;
    }
}
