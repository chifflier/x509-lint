use super::{CertificateLint, LintDefinition, CertificateLintRegistry, LintResult, LintStatus};

mod extensions;
mod name;
mod rfc5280;

/// Return a [`CertificateLintRegistry`] containing all RFC lints included in this crate
/// for X.509 Certificates
pub fn rfc_lints<'a>() -> CertificateLintRegistry<'a> {
    let all_rfc_lints = [
        rfc5280::RFC_LINTS,
        name::NAME_LINTS,
        extensions::EXTENSION_LINTS,
    ]
    .concat();
    CertificateLintRegistry::new(all_rfc_lints)
}

#[cfg(test)]
mod tests {
    use x509_parser::prelude::{FromDer, X509Certificate};

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
