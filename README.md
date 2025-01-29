[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE-MIT)
[![Apache License 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE-APACHE)
[![docs.rs](https://docs.rs/x509_lint/badge.svg)](https://docs.rs/x509_lint)
[![crates.io](https://img.shields.io/crates/v/x509_lint.svg)](https://crates.io/crates/x509_lint)
[![Download numbers](https://img.shields.io/crates/d/x509_lint.svg)](https://crates.io/crates/x509_lint)
[![Github CI](https://github.com/chifflier/x509-lint/workflows/Continuous%20integration/badge.svg)](https://github.com/chifflier/x509-lint/actions)
[![Minimum rustc version](https://img.shields.io/badge/rustc-1.70.0+-lightgray.svg)](#rust-version-requirements)

# x509-lint

`x509-lint` is a X.509 Certificates and Certificate Revocation List linter written in Rust.
It runs a set of checks, taken from
[RFC5280](https://datatracker.ietf.org/doc/html/rfc5280) and other sources.

This repository provides both the command-line tool ([`x509lint`](https://crates.io/crates/x509lint))
and a Rust library ([`x509_lint`](https://crates.io/crates/x509_lint)) which can be
embeded in other Rust programs to use either the included lints, or custom ones.

# `x509lint` binary tool

Compile and install `x509lint`:
```shell
$ cargo install x509lint
```

Run the binary to display lint warnings and errors on certificates:
```shell
$ x509lint issuerFieldMissing.pem
Subject: C=US, ST=FL, L=Tallahassee, streetAddress=3210 Holly Mill Run, postalCode=30062, O=Extreme Discord, OU=Chaos, CN=gov.us
  [error] The issuer field MUST contain a non-empty distinguished name (DN)  citation:RFC5280: 4.1.2.4
```

The tool accepts input files in DER or PEM format.

# Using `x509_lint` library

Use `cargo add` or edit the cargo manifest `Cargo.toml` to add a dependency on `x509_lint`:
```
cargo add x509_lint
```

See [x509_lint documentation](https://docs.rs/x509-lint/) for details on crate functions and examples.

The crate expects an object [`X509Certificate`](https://docs.rs/x509-parser/latest/x509_parser/certificate/struct.X509Certificate.html) as input.
To parse DER or PEM certificate data and create an `X509Certificate` object, use the [x509-parser](https://crates.io/crates/x509-parser/) crate.

## Rust version requirements

`x509-lint` requires **Rustc version 1.70.0 or greater**

## Changes

See [CHANGELOG.md](CHANGELOG.md)

# License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
