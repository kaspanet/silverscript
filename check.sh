#!/usr/bin/env bash
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

run_check() {
    cargo check --tests --workspace --benches
}

run_tests() {
    if cargo nextest --version >/dev/null 2>&1; then
        cargo nextest run --release --workspace
    else
        cargo test --release --workspace
    fi
}

run_lints() {
    cargo fmt --all -- --check
    cargo clippy --workspace --tests --benches --examples -- -D warnings
}

run_tree_sitter_tests() {
    cargo test --manifest-path tree-sitter/Cargo.toml
}

case "${1:-all}" in
    all)
        cargo fmt --all
        run_check
        cargo clippy --workspace --tests --benches --examples -- -D warnings
        run_tests
        run_tree_sitter_tests
        ;;
    check)
        run_check
        ;;
    test)
        run_tests
        ;;
    lint)
        run_lints
        ;;
    tree-sitter)
        run_tree_sitter_tests
        ;;
    -h|--help)
        echo "Usage: ./check.sh [all|check|test|lint|tree-sitter]"
        echo "The default 'all' check applies Rust formatting before validation."
        ;;
    *)
        echo "unknown check: $1" >&2
        echo "try: ./check.sh --help" >&2
        exit 2
        ;;
esac
