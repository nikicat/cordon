# cordon task runner — https://just.systems  (install: `cargo install just`)
#
# Recipes are gated to the OS they apply to. The eBPF build is Linux-only because
# eBPF is a Linux-kernel facility; the planned macOS Endpoint Security backend is a
# separate build path and will get its own `[macos]` recipes here.

# List available recipes.
default:
    @just --list

# Build the userspace workspace (core, daemon, cli, bpf-common) on stable.
build:
    cargo build --workspace

# Run the test suite + lints (what CI gates on).
test:
    cargo test --workspace
    cargo clippy --workspace --all-targets -- -D warnings
    cargo fmt --all --check

# Build the eBPF object and stage it at target/bpf/cordon.bpf.o (Linux only).
[linux]
build-ebpf:
    #!/usr/bin/env bash
    set -euo pipefail
    # Prerequisites (declared, not discovered):
    #   - pinned nightly + rust-src — crates/bpf/rust-toolchain.toml (auto-fetched)
    #   - bpf-linker on PATH — `cargo install bpf-linker`
    cd crates/bpf
    cargo build --release
    mkdir -p ../../target/bpf
    cp target/bpfel-unknown-none/release/cordon ../../target/bpf/cordon.bpf.o
    echo "staged eBPF object → target/bpf/cordon.bpf.o"

# Build the daemon (the bpf-lsm backend is on by default; Linux only).
[linux]
build-bpf-daemon:
    cargo build -p cordon-daemon
