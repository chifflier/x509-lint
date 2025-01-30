use x509_lint::x509_parser::prelude::CertificateRevocationList;
use x509_lint::{crl_rfc_lints, x509_parser, CRLLintRegistry, LintDefinition, LintResult};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use colored::Colorize;
use std::error::Error;
use std::io;
use x509_lint::{rfc_lints, CertificateLintRegistry};
use x509_parser::pem::*;
use x509_parser::prelude::{FromDer, X509Certificate};

use clap::{CommandFactory, FromArgMatches, Parser};

/// Extract information in JSON format from a X.509 certificate
#[derive(Debug, Parser)]
#[clap(name = "x509lint")]
#[clap(author)]
#[clap(version)]
#[clap(about = "X.509 Certificates and Certificate Revocation List linter written in Rust", long_about = None)]
pub struct Args {
    // // Enable color for output
    // #[clap(long)]
    // color: bool,
    /// Print all registered lints and exit
    #[clap(long)]
    print_lints: bool,

    /// Force interpreting file as certificate (default: auto-detect)
    #[clap(long = "cert")]
    force_cert: bool,

    /// Force interpreting file as CRL (default: auto-detect)
    #[clap(long = "crl")]
    force_crl: bool,

    /// Input file, or standard input if none was provided
    #[clap(group = "input")]
    input_file: Option<String>,
}

struct Registries<'a> {
    cert: CertificateLintRegistry<'a>,
    crl: CRLLintRegistry<'a>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Args::command().help_template(
        "\
{before-help}{name} {version} - {author-with-newline}
{about-with-newline}
{usage-heading} {usage}

{all-args}{after-help}
",
    );
    let matches = cli.get_matches();
    let args = Args::from_arg_matches(&matches).unwrap();
    if args.print_lints {
        print_lints();
        std::process::exit(0);
    }

    match process_certs(&args) {
        Ok(_) => Ok(()),
        Err(e) => {
            println!("{e}");
            Ok(())
        }
    }
}

fn print_lints() {
    println!("Certificate Lints:");
    let cert_registry = rfc_lints();

    for (lint_definition, _) in cert_registry.lints() {
        print_lint(lint_definition);
    }

    println!("CRL Lints:");
    let crl_registry = crl_rfc_lints();

    for (lint_definition, _) in crl_registry.lints() {
        print_lint(lint_definition);
    }
}

fn print_lint(lint_definition: &LintDefinition<'_>) {
    let mut s = String::new();
    s += &format!(
        " - [{}]: {}",
        lint_definition.name().bold(),
        lint_definition.description()
    );
    if let Some(citation) = lint_definition.citation() {
        s += &(format!("  citation:{}", citation.bright_white()));
    }

    println!("{s}");
}

fn process_certs(args: &Args) -> Result<(), Box<dyn Error>> {
    let cert_registry = rfc_lints();
    let crl_registry = crl_rfc_lints();

    let reg = Registries {
        cert: cert_registry,
        crl: crl_registry,
    };

    // read file or stdin
    let mut input: Box<dyn std::io::Read + 'static> = if let Some(input_file) = &args.input_file {
        let f = std::fs::File::open(input_file)?;
        Box::new(f)
    } else {
        Box::new(io::stdin())
    };

    const BUFFER_SIZE: usize = 128 * 1024;
    let mut buffer_vec = Vec::with_capacity(BUFFER_SIZE);

    input.read_to_end(&mut buffer_vec)?;

    let data = &buffer_vec;

    // try to guess if PEM, base64 or DER
    if data.starts_with(b"Certificate:\n") {
        // probably a PEM file with text data before base64
        if let Ok(text) = std::str::from_utf8(data) {
            // skip text
            if let Some(index) = text.find("\n---") {
                // skip 1 byte (\n) and test if PEM
                let data = &text.as_bytes()[index + 1..];

                for pem in Pem::iter_from_buffer(data) {
                    let pem = pem?;
                    if pem.label.as_str() != "CERTIFICATE" {
                        eprintln!("Warning: PEM is not a certificate?!");
                    }
                    let der = &pem.contents;
                    x509_lint(der, args, &reg)?;
                }
            }
        }
    } else if &data[..3] == b"---" {
        // probably PEM
        for pem in Pem::iter_from_buffer(data) {
            let pem = pem?;
            if pem.label.as_str() != "CERTIFICATE" {
                eprintln!("Warning: PEM is not a certificate?!");
            }
            let der = &pem.contents;
            x509_lint(der, args, &reg)?;
        }
    } else if test_base64(data) {
        // base64
        let der = STANDARD.decode(data)?;
        x509_lint(&der, args, &reg)?;
    } else if data.starts_with(&[0x30]) {
        // DER
        x509_lint(data, args, &reg)?;
    } else {
        eprintln!("Could not determine input format");
        std::process::exit(2);
    }

    Ok(())
}

fn x509_lint(der: &[u8], args: &Args, reg: &Registries) -> Result<(), Box<dyn Error>> {
    let lint_results = if args.force_cert {
        x509_cert_lint(der, args, &reg.cert)?
    } else if args.force_crl {
        x509_crl_lint(der, args, &reg.crl)?
    } else {
        // auto-detect: try as certificate, if not as CRL
        match x509_cert_lint(der, args, &reg.cert) {
            Ok(t) => t,
            Err(_) => x509_crl_lint(der, args, &reg.crl)?,
        }
    };

    if lint_results.is_empty() {
        println!("  No warnings/errors");
    }
    for (lint_definition, lint_result) in lint_results.iter() {
        let mut s = String::new();
        let status = match lint_result.status {
            x509_lint::LintStatus::Pass => "pass".green(),
            x509_lint::LintStatus::Warn => "warn".yellow(),
            x509_lint::LintStatus::Error => "error".red(),
        };
        s += &format!("  [{status}] {}", lint_definition.description().bold());
        if let Some(citation) = lint_definition.citation() {
            s += &(format!("  citation:{}", citation.bright_white()));
        }
        if let Some(details) = lint_result.details.as_ref() {
            s += &format!("  details:{}", details);
        }

        println!("{s}");
    }

    Ok(())
}

fn x509_cert_lint<'a>(
    der: &'a [u8],
    _args: &'a Args,
    registry: &'a CertificateLintRegistry<'a>,
) -> Result<Vec<(&'a LintDefinition<'a>, LintResult)>, Box<dyn Error>> {
    let (_rem, x509) = X509Certificate::from_der(der)?;

    println!("Subject: {}", x509.subject());

    let lint_results = registry.run_lints(&x509);
    Ok(lint_results)
}

fn x509_crl_lint<'a>(
    der: &'a [u8],
    _args: &'a Args,
    registry: &'a CRLLintRegistry<'a>,
) -> Result<Vec<(&'a LintDefinition<'a>, LintResult)>, Box<dyn Error>> {
    let (_rem, crl) = CertificateRevocationList::from_der(der)?;

    println!("CRL Issuer: {}", crl.issuer());

    let lint_results = registry.run_lints(&crl);
    Ok(lint_results)
}

// attempt to guess if data is base64-encoded
fn test_base64(data: &[u8]) -> bool {
    if data.len() % 4 == 0 && data.last() == Some(&b'=') {
        // test if starts by data in ranges A-Z a-z 0-9 +/=
    }
    false
}
