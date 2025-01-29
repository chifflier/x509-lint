[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE-MIT)
[![Apache License 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE-APACHE)
[![Github CI](https://github.com/chifflier/x509-lint/workflows/Continuous%20integration/badge.svg)](https://github.com/chifflier/x509-lint/actions)

# x509-lint

This repository contains both a Rust library ([x509_lint](x509_lint)) to define
and run lints on X.509 objects (Certificates and CRLs), and a tool
([x509lint](src/main.rs)) to run preconfigured lints on certificate files.

# `x509lint` binary tool

Compile and install `x509lint`.

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
