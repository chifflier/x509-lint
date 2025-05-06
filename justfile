set positional-arguments

build:
    cargo build --all-targets --all-features

build-doc:
    RUSTDOCFLAGS="--cfg docsrs" cargo +nightly doc --workspace --no-deps --all-features

build-examples:
    cargo build --all-features --examples

clean:
    cargo clean

check-all:
    cargo check --all-features
    cargo check --all-features --examples

check-clippy:
    # cargo clippy --all-features -- -D warnings
    cargo +nightly clippy --manifest-path x509_lint/Cargo.toml --all-features -- -D warnings &&\
    cargo +nightly clippy --manifest-path Cargo.toml --all-features -- -D warnings

check-fmt:
    cargo fmt --check

check-nostd:
    cargo clean
    cargo check --no-default-features

doc-all:
    cargo doc --all-features

test-all:
    #cargo test --all-features -- --nocapture
    cargo nextest run --all-features

test-doc:
    cargo test --doc

test *args='':
    # cargo test --all-features -- --nocapture "$@"
    cargo nextest run --all-features -- "$@"

test-v *args='':
    # cargo test --all-features -- --nocapture "$@"
    cargo nextest run --all-features --no-capture -- "$@"

semver-checks:
    cargo semver-checks check-release

check-before-release:
    just check-fmt
    just check-nostd
    just clean
    just check-all test-all test-doc check-clippy semver-checks doc-all
    just clean
    cargo package
