# IDA MCP Server

# Show available recipes
default:
    @just --list

# Build debug binary
build:
    cargo build

# Build release binary
release:
    cargo build --release

# Build and publish prerelease (macOS ARM64 only, for local testing)
prerelease ida_version="9.4": && (update-beta-cask ida_version)
    #!/usr/bin/env bash
    set -euo pipefail
    VERSION=$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')
    IDADIR="/Applications/IDA Professional {{ ida_version }}.app/Contents/MacOS" cargo build --release
    mkdir -p dist
    rm -f "dist/ida-mcp_${VERSION}_Darwin_arm64.tar.gz"
    tar -czvf "dist/ida-mcp_${VERSION}_Darwin_arm64.tar.gz" -C target/release ida-mcp -C "{{ justfile_directory() }}" README.md LICENSE
    gh release create "v${VERSION}" \
        --prerelease \
        --title "IDA Pro MCP Server v${VERSION}" \
        --notes "Prerelease for IDA Pro {{ ida_version }} beta. Requires IDA Pro {{ ida_version }} with valid license." \
        "dist/ida-mcp_${VERSION}_Darwin_arm64.tar.gz"

# Update homebrew beta cask in tap
update-beta-cask ida_version="9.4":
    #!/usr/bin/env bash
    set -euo pipefail
    VERSION=$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')
    just --justfile "{{ justfile_directory() }}/ci.just" publish-beta-cask "$VERSION" "{{ ida_version }}"

# Update homebrew stable cask in tap (run after GitHub release is created).
# Supports macOS (arm64, x86_64) and Linux (x86_64, arm64).
update-cask revision="":
    #!/usr/bin/env bash
    set -euo pipefail
    VERSION=$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')
    just release-fetch-checksums "$VERSION"
    just --justfile "{{ justfile_directory() }}/ci.just" publish-cask "$VERSION" "{{ revision }}"

# Update homebrew versioned cask for a specific IDA version.
# Usage: just update-versioned-cask 9.2
# Resolves the latest release tag for that IDA line automatically.
update-versioned-cask ida_version release_version="":
    #!/usr/bin/env bash
    set -euo pipefail
    IDA_VERSION="{{ ida_version }}"
    VERSION="{{ release_version }}"
    if [[ -z "$VERSION" ]]; then
        VERSION=$(git tag --list "v${IDA_VERSION}.*" --sort=-version:refname | head -1 | sed 's/^v//')
    fi
    if [[ -z "$VERSION" ]]; then
        echo "Error: no release tag found for IDA ${IDA_VERSION}"
        exit 1
    fi
    just --justfile "{{ justfile_directory() }}/ci.just" publish-versioned-cask "$VERSION" "{{ ida_version }}"

# CI helper wrappers. The implementation lives in ci.just so workflow shell logic
# stays centralized and easier to audit.
ci-package-artifacts:
    just --justfile "{{ justfile_directory() }}/ci.just" package-artifacts

ci-generate-checksums:
    just --justfile "{{ justfile_directory() }}/ci.just" generate-checksums

# Local post-release publishing. These use your local `gh` auth and the live
# GitHub release assets/checksums rather than CI secrets or ephemeral artifacts.
release-fetch-checksums version="":
    #!/usr/bin/env bash
    set -euo pipefail
    VERSION="{{ version }}"
    if [[ -z "$VERSION" ]]; then
        VERSION=$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')
    fi
    just --justfile "{{ justfile_directory() }}/ci.just" download-checksums "$VERSION"

release-sync-scoop version="":
    #!/usr/bin/env bash
    set -euo pipefail
    VERSION="{{ version }}"
    if [[ -z "$VERSION" ]]; then
        VERSION=$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')
    fi
    just release-fetch-checksums "$VERSION"
    just --justfile "{{ justfile_directory() }}/ci.just" publish-scoop "$VERSION"

release-sync-nur version="":
    #!/usr/bin/env bash
    set -euo pipefail
    VERSION="{{ version }}"
    if [[ -z "$VERSION" ]]; then
        VERSION=$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')
    fi
    just release-fetch-checksums "$VERSION"
    just --justfile "{{ justfile_directory() }}/ci.just" publish-nur "$VERSION"

release-sync-winget version="":
    #!/usr/bin/env bash
    set -euo pipefail
    VERSION="{{ version }}"
    if [[ -z "$VERSION" ]]; then
        VERSION=$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')
    fi
    just release-fetch-checksums "$VERSION"
    just --justfile "{{ justfile_directory() }}/ci.just" publish-winget "$VERSION"

release-sync version="":
    #!/usr/bin/env bash
    set -euo pipefail
    VERSION="{{ version }}"
    if [[ -z "$VERSION" ]]; then
        VERSION=$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')
    fi
    just release-fetch-checksums "$VERSION"
    just --justfile "{{ justfile_directory() }}/ci.just" publish-cask "$VERSION"
    just --justfile "{{ justfile_directory() }}/ci.just" publish-scoop "$VERSION"
    just --justfile "{{ justfile_directory() }}/ci.just" publish-nur "$VERSION"
    just --justfile "{{ justfile_directory() }}/ci.just" publish-winget "$VERSION"

# Run integration test (debug)
test: build
    cd test && SERVER_BIN=../target/debug/ida-mcp RUST_LOG=ida_mcp=trace just test

# Run HTTP integration test (debug)
test-http: build
    cd test && SERVER_BIN=../target/debug/ida-mcp RUST_LOG=ida_mcp=trace just test-http

# Run IDAPython script integration test (debug)
test-script: build
    cd test && SERVER_BIN=../target/debug/ida-mcp RUST_LOG=ida_mcp=trace just test-script

# Run cargo unit tests
cargo-test:
    RUST_BACKTRACE=1 cargo test

# Format code
fmt:
    cargo fmt --all

# Run clippy linter
lint:
    cargo clippy -- -D warnings

# Run full check (fmt + lint + test)
check: fmt lint cargo-test

# Clean build artifacts
clean:
    cargo clean
    rm -rf dist/

# Bump version and push tag
bump:
    git tag $(svu patch)
    git push --tags
