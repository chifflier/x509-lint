use x509_parser::certificate::X509Certificate;

use super::*;

/// Prototype for X.509 certificate lint function
pub type CertificateLint = fn(_x509: &X509Certificate) -> LintResult;

/// Helper macro to define a new lint
///
/// If $link_fn returns true, emit lint warning
#[macro_export]
macro_rules! certificate_lint {
    ($vis:vis $lint_fn:ident, $lvl:expr, $lint:expr) => {
        $vis fn $lint_fn(x509: &x509_parser::certificate::X509Certificate) -> LintResult {
            let f = $lint;
            if f(x509) {
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
    certificate_lint!(test_lint1, LintStatus::Error, |x509: &X509Certificate| x509
        .version
        .0
        >= 3);

    #[test]
    fn test_cert_macro() {
        let _ = test_lint1;
    }
}
