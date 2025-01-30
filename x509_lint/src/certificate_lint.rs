use x509_parser::certificate::X509Certificate;

use super::*;

/// Prototype for X.509 certificate lint function
///
/// # Example
///
/// ```rust
/// use x509_lint::*;
/// use x509_lint::x509_parser::prelude::X509Certificate;
///
/// fn test_cert_version(x509: &X509Certificate<'_>) -> LintResult {
///     if x509.version().0 >= 3 {
///         LintResult::new(LintStatus::Error)
///     } else {
///         LintResult::pass()
///     }
/// }
/// ```
pub type CertificateLint = fn(_x509: &X509Certificate) -> LintResult;

/// Helper macro to implement a new [`CertificateLint`]
///
/// If `$link_fn` returns true, emit lint warning
///
/// _Note_: This macro is mostly useful if the test is small and simple. In other
/// cases, it is best to implement a function with [`CertificateLint`] signature.
///
/// # Example
///
/// ```rust
/// use x509_lint::*;
/// use x509_lint::x509_parser::prelude::X509Certificate;
///
/// certificate_lint!(
///     test_cert_version,
///     LintStatus::Error,
///     |x509: &X509Certificate<'_>| x509.version().0 >= 3
/// );
/// ```
#[macro_export]
macro_rules! certificate_lint {
    ($vis:vis $lint_fn:ident, $lvl:expr, $lint:expr) => {
        #[allow(unused_qualifications)]
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
