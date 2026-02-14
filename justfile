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
    TARBALL="dist/ida-mcp_${VERSION}_Darwin_arm64.tar.gz"
    SHA256=$(shasum -a 256 "$TARBALL" | awk '{print $1}')
    TAP_DIR="${HOME}/Developer/Mine/blacktop/homebrew-tap"

    if [[ ! -d "$TAP_DIR" ]]; then
        echo "Error: homebrew-tap not found at $TAP_DIR"
        exit 1
    fi

    cat > "$TAP_DIR/Casks/ida-mcp@beta.rb" << EOF
    # This file is auto-generated. DO NOT EDIT.
    cask "ida-mcp@beta" do
      version "${VERSION}"
      sha256 "${SHA256}"

      url "https://github.com/blacktop/ida-mcp-rs/releases/download/v#{version}/ida-mcp_#{version}_Darwin_arm64.tar.gz"
      name "ida-mcp (beta)"
      desc "Headless IDA Pro MCP Server for AI-powered binary analysis (beta)"
      homepage "https://github.com/blacktop/ida-mcp-rs"

      conflicts_with cask: "ida-mcp"

      binary "ida-mcp"

      postflight do
        Dir.glob("#{staged_path}/**/ida-mcp").each do |f|
          system_command "/usr/bin/xattr", args: ["-dr", "com.apple.quarantine", f]
        end
      end

      caveats do
        <<~EOS
          ida-mcp@beta requires IDA Pro {{ ida_version }}+ to be installed.
          This is a prerelease version for testing.

          Standard IDA installations work automatically:
            claude mcp add ida -- ida-mcp

          If using a non-standard path, set DYLD_LIBRARY_PATH:
            claude mcp add ida -e DYLD_LIBRARY_PATH='/path/to/ida/Contents/MacOS' -- ida-mcp
        EOS
      end
    end
    EOF

    echo "Generated $TAP_DIR/Casks/ida-mcp@beta.rb"
    cd "$TAP_DIR"
    git add "Casks/ida-mcp@beta.rb"
    git commit -m "Update ida-mcp@beta to ${VERSION}"
    git push
    echo "Pushed beta cask to homebrew-tap"

# Update homebrew stable cask in tap (run after GitHub release is created)
update-cask:
    #!/usr/bin/env bash
    set -euo pipefail
    VERSION=$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')
    TAP_DIR="${HOME}/Developer/Mine/blacktop/homebrew-tap"
    TARBALL_URL="https://github.com/blacktop/ida-mcp-rs/releases/download/v${VERSION}/ida-mcp_${VERSION}_Darwin_arm64.tar.gz"

    if [[ ! -d "$TAP_DIR" ]]; then
        echo "Error: homebrew-tap not found at $TAP_DIR"
        exit 1
    fi

    # Download tarball to get SHA256
    echo "Downloading release tarball..."
    mkdir -p dist
    curl -sL "$TARBALL_URL" -o "dist/ida-mcp_${VERSION}_Darwin_arm64.tar.gz"
    SHA256=$(shasum -a 256 "dist/ida-mcp_${VERSION}_Darwin_arm64.tar.gz" | awk '{print $1}')

    cat > "$TAP_DIR/Casks/ida-mcp.rb" << EOF
    # This file is auto-generated. DO NOT EDIT.
    cask "ida-mcp" do
      version "${VERSION}"
      sha256 "${SHA256}"

      url "https://github.com/blacktop/ida-mcp-rs/releases/download/v#{version}/ida-mcp_#{version}_Darwin_arm64.tar.gz"
      name "ida-mcp"
      desc "Headless IDA Pro MCP Server for AI-powered binary analysis"
      homepage "https://github.com/blacktop/ida-mcp-rs"

      conflicts_with cask: "ida-mcp@beta"

      binary "ida-mcp"

      postflight do
        Dir.glob("#{staged_path}/**/ida-mcp").each do |f|
          system_command "/usr/bin/xattr", args: ["-dr", "com.apple.quarantine", f]
        end
      end

      caveats do
        <<~EOS
          ida-mcp requires IDA Pro 9.2+ to be installed.

          Standard IDA installations work automatically:
            claude mcp add ida -- ida-mcp

          If using a non-standard path, set DYLD_LIBRARY_PATH:
            claude mcp add ida -e DYLD_LIBRARY_PATH='/path/to/ida/Contents/MacOS' -- ida-mcp
        EOS
      end
    end
    EOF

    echo "Generated $TAP_DIR/Casks/ida-mcp.rb"
    cd "$TAP_DIR"
    git add "Casks/ida-mcp.rb"
    git commit -m "Update ida-mcp to ${VERSION}"
    git push
    echo "Pushed stable cask to homebrew-tap"

# Run integration test (debug)
test: build
    cd test && SERVER_BIN=../target/debug/ida-mcp RUST_LOG=ida_mcp=trace just test

# Run HTTP integration test (debug)
test-http: build
    cd test && SERVER_BIN=../target/debug/ida-mcp RUST_LOG=ida_mcp=trace just test-http

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
