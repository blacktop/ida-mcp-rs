# Shared release helpers used by CI packaging and local post-release publishing.

package-artifacts:
    #!/usr/bin/env bash
    set -euo pipefail
    VERSION="${GITHUB_REF_NAME#v}"
    cd artifacts

    package_tar() {
        local source_dir="$1"
        local archive_name="$2"
        chmod +x "${source_dir}/ida-mcp"
        tar -czvf "${archive_name}" \
            -C "${source_dir}" ida-mcp \
            -C "${GITHUB_WORKSPACE}" README.md LICENSE
    }

    package_zip() {
        local source_dir="$1"
        local archive_name="$2"
        zip "${archive_name}" \
            "${source_dir}/ida-mcp.exe" \
            -j "${GITHUB_WORKSPACE}/README.md" \
            -j "${GITHUB_WORKSPACE}/LICENSE"
    }

    package_tar ida-mcp-linux-x86_64 "ida-mcp_${VERSION}_Linux_x86_64.tar.gz"
    package_tar ida-mcp-macos-x86_64 "ida-mcp_${VERSION}_Darwin_x86_64.tar.gz"
    package_tar ida-mcp-macos-arm64 "ida-mcp_${VERSION}_Darwin_arm64.tar.gz"
    package_zip ida-mcp-windows-x86_64 "ida-mcp_${VERSION}_Windows_x86_64.zip"

generate-checksums:
    #!/usr/bin/env bash
    set -euo pipefail
    cd artifacts
    shasum -a 256 *.tar.gz *.zip > checksums.txt

download-checksums version:
    #!/usr/bin/env bash
    set -euo pipefail
    VERSION="{{ version }}"
    WORKDIR="dist/release-sync/${VERSION}"
    mkdir -p "${WORKDIR}"
    gh release download "v${VERSION}" \
        --pattern "checksums.txt" \
        --clobber \
        --dir "${WORKDIR}"

publish-scoop version:
    #!/usr/bin/env bash
    set -euo pipefail
    VERSION="{{ version }}"
    WORKDIR="dist/release-sync/${VERSION}"
    CHECKSUMS_FILE="${WORKDIR}/checksums.txt"
    : "${VERSION:?VERSION is required}"
    [ -f "${CHECKSUMS_FILE}" ] || { echo "Missing ${CHECKSUMS_FILE}. Run download-checksums ${VERSION} first."; exit 1; }
    gh auth status >/dev/null
    GH_AUTH_TOKEN="$(gh auth token)"

    hash_for() { grep "$1" "${CHECKSUMS_FILE}" | awk '{print $1}'; }
    WIN_X86_64_HASH=$(hash_for "Windows_x86_64.zip")
    cat > "${WORKDIR}/ida-mcp.json" <<'TEMPLATE'
    {
      "version": "VERSION_PLACEHOLDER",
      "architecture": {
        "64bit": {
          "url": "URL_PLACEHOLDER",
          "bin": ["ida-mcp.exe"],
          "hash": "HASH_PLACEHOLDER"
        }
      },
      "homepage": "https://github.com/blacktop/ida-mcp-rs",
      "license": "MIT",
      "description": "Headless IDA Pro MCP Server for AI-powered binary analysis",
      "post_install": [
        "$idaPaths = @(",
        "  'C:\\Program Files\\IDA Professional 9.3',",
        "  'C:\\Program Files\\IDA Pro 9.3',",
        "  'C:\\Program Files\\IDA Home 9.3',",
        "  'C:\\Program Files\\IDA Essential 9.3',",
        "  'C:\\Program Files\\IDA Professional 9.2',",
        "  'C:\\Program Files\\IDA Pro 9.2'",
        ")",
        "$found = $idaPaths | Where-Object { Test-Path \"$_\\idalib.dll\" } | Select-Object -First 1",
        "if ($found -and -not $env:IDADIR) {",
        "  [Environment]::SetEnvironmentVariable('IDADIR', $found, 'User')",
        "  $env:IDADIR = $found",
        "  Write-Host \"IDADIR set to $found\"",
        "} elseif (-not $found) {",
        "  Write-Host 'IDA Pro not found in standard locations. Set IDADIR manually or add IDA to PATH.'",
        "}"
      ],
      "post_uninstall": [
        "$idaPaths = @(",
        "  'C:\\Program Files\\IDA Professional 9.3',",
        "  'C:\\Program Files\\IDA Pro 9.3',",
        "  'C:\\Program Files\\IDA Home 9.3',",
        "  'C:\\Program Files\\IDA Essential 9.3',",
        "  'C:\\Program Files\\IDA Professional 9.2',",
        "  'C:\\Program Files\\IDA Pro 9.2'",
        ")",
        "$current = [Environment]::GetEnvironmentVariable('IDADIR', 'User')",
        "if ($current -and ($idaPaths -contains $current)) {",
        "  [Environment]::SetEnvironmentVariable('IDADIR', $null, 'User')",
        "  Write-Host 'Removed IDADIR environment variable'",
        "}"
      ],
      "notes": "Requires IDA Pro 9.x with a valid license. IDADIR is auto-detected from standard install paths."
    }
TEMPLATE
    # Replace placeholders with actual values (avoids heredoc variable expansion issues)
    sed -i'' -e "s|VERSION_PLACEHOLDER|${VERSION}|g" \
             -e "s|URL_PLACEHOLDER|https://github.com/blacktop/ida-mcp-rs/releases/download/v${VERSION}/ida-mcp_${VERSION}_Windows_x86_64.zip|g" \
             -e "s|HASH_PLACEHOLDER|${WIN_X86_64_HASH}|g" \
             "${WORKDIR}/ida-mcp.json"

    TMPDIR="$(mktemp -d)"
    git clone "https://x-access-token:${GH_AUTH_TOKEN}@github.com/blacktop/scoop-bucket.git" "${TMPDIR}"
    cp "${WORKDIR}/ida-mcp.json" "${TMPDIR}/"

    cd "${TMPDIR}"
    git config user.name "github-actions[bot]"
    git config user.email "github-actions[bot]@users.noreply.github.com"
    git add ida-mcp.json
    git diff --cached --quiet || git commit -m "ida-mcp: v${VERSION}"
    git push

publish-nur version:
    #!/usr/bin/env bash
    set -euo pipefail
    VERSION="{{ version }}"
    WORKDIR="dist/release-sync/${VERSION}"
    CHECKSUMS_FILE="${WORKDIR}/checksums.txt"
    : "${VERSION:?VERSION is required}"
    [ -f "${CHECKSUMS_FILE}" ] || { echo "Missing ${CHECKSUMS_FILE}. Run download-checksums ${VERSION} first."; exit 1; }
    gh auth status >/dev/null
    GH_AUTH_TOKEN="$(gh auth token)"

    hash_for() { grep "$1" "${CHECKSUMS_FILE}" | awk '{print $1}'; }
    nix_sri() {
        echo -n "sha256-$(echo "$1" | xxd -r -p | base64 | tr -d '\n')"
    }

    LINUX_X86_64_SRI=$(nix_sri "$(hash_for "Linux_x86_64.tar.gz")")
    DARWIN_X86_64_SRI=$(nix_sri "$(hash_for "Darwin_x86_64.tar.gz")")
    DARWIN_ARM64_SRI=$(nix_sri "$(hash_for "Darwin_arm64.tar.gz")")

    cat > "${WORKDIR}/ida-mcp-default.nix" <<'NIXEOF'
    {
      lib,
      fetchurl,
      stdenvNoCC,
    }:
    let
      inherit (stdenvNoCC.hostPlatform) system;
      supported = {
        x86_64-linux = {
          url = "https://github.com/blacktop/ida-mcp-rs/releases/download/vVERSION_PLACEHOLDER/ida-mcp_VERSION_PLACEHOLDER_Linux_x86_64.tar.gz";
          hash = "LINUX_X86_64_HASH_PLACEHOLDER";
        };
        x86_64-darwin = {
          url = "https://github.com/blacktop/ida-mcp-rs/releases/download/vVERSION_PLACEHOLDER/ida-mcp_VERSION_PLACEHOLDER_Darwin_x86_64.tar.gz";
          hash = "DARWIN_X86_64_HASH_PLACEHOLDER";
        };
        aarch64-darwin = {
          url = "https://github.com/blacktop/ida-mcp-rs/releases/download/vVERSION_PLACEHOLDER/ida-mcp_VERSION_PLACEHOLDER_Darwin_arm64.tar.gz";
          hash = "DARWIN_ARM64_HASH_PLACEHOLDER";
        };
      };
      platform = supported.${system} or (throw "ida-mcp: unsupported system ${system}");
    in
    stdenvNoCC.mkDerivation {
      pname = "ida-mcp";
      version = "VERSION_PLACEHOLDER";
      src = fetchurl {
        url = platform.url;
        sha256 = platform.hash;
      };
      sourceRoot = ".";
      installPhase = ''
        mkdir -p $out/bin
        cp -v ./ida-mcp $out/bin/ida-mcp
      '';
      meta = {
        description = "Headless IDA Pro MCP Server for AI-powered binary analysis";
        homepage = "https://github.com/blacktop/ida-mcp-rs";
        license = lib.licenses.mit;
        sourceProvenance = [ lib.sourceTypes.binaryNativeCode ];
        platforms = lib.attrNames supported;
      };
    }
    NIXEOF

    sed -i.bak \
        -e "s|VERSION_PLACEHOLDER|${VERSION}|g" \
        -e "s|LINUX_X86_64_HASH_PLACEHOLDER|${LINUX_X86_64_SRI}|g" \
        -e "s|DARWIN_X86_64_HASH_PLACEHOLDER|${DARWIN_X86_64_SRI}|g" \
        -e "s|DARWIN_ARM64_HASH_PLACEHOLDER|${DARWIN_ARM64_SRI}|g" \
        "${WORKDIR}/ida-mcp-default.nix"
    rm -f "${WORKDIR}/ida-mcp-default.nix.bak"

    TMPDIR="$(mktemp -d)"
    git clone "https://x-access-token:${GH_AUTH_TOKEN}@github.com/blacktop/nur.git" "${TMPDIR}"

    cd "${TMPDIR}"
    mkdir -p pkgs/ida-mcp
    cp "${OLDPWD}/${WORKDIR}/ida-mcp-default.nix" pkgs/ida-mcp/default.nix
    if ! grep -q 'ida-mcp' default.nix; then
        awk '
            /ipsw = / && !done {
                print
                print "  ida-mcp = pkgs.callPackage ./pkgs/ida-mcp { };"
                done = 1
                next
            }
            { print }
        ' default.nix > default.nix.tmp
        mv default.nix.tmp default.nix
    fi

    git config user.name "github-actions[bot]"
    git config user.email "github-actions[bot]@users.noreply.github.com"
    git add pkgs/ida-mcp/default.nix default.nix
    git diff --cached --quiet || git commit -m "ida-mcp: v${VERSION}"
    git push

publish-winget version:
    #!/usr/bin/env bash
    set -euo pipefail
    VERSION="{{ version }}"
    WORKDIR="dist/release-sync/${VERSION}"
    CHECKSUMS_FILE="${WORKDIR}/checksums.txt"
    : "${VERSION:?VERSION is required}"
    [ -f "${CHECKSUMS_FILE}" ] || { echo "Missing ${CHECKSUMS_FILE}. Run download-checksums ${VERSION} first."; exit 1; }
    gh auth status >/dev/null
    GH_AUTH_TOKEN="$(gh auth token)"

    hash_for() { grep "$1" "${CHECKSUMS_FILE}" | awk '{print $1}'; }
    WIN_X86_64_HASH_UPPER=$(hash_for "Windows_x86_64.zip" | tr '[:lower:]' '[:upper:]')
    LOCAL_MANIFEST_DIR="${WORKDIR}/manifests/b/blacktop/ida-mcp/${VERSION}"
    REMOTE_MANIFEST_DIR="manifests/b/blacktop/ida-mcp/${VERSION}"
    BRANCH="ida-mcp-${VERSION}"

    mkdir -p "${LOCAL_MANIFEST_DIR}"

    cat > "${LOCAL_MANIFEST_DIR}/blacktop.ida-mcp.yaml" <<EOF
    # yaml-language-server: \$schema=https://aka.ms/winget-manifest.version.1.6.0.schema.json
    PackageIdentifier: blacktop.ida-mcp
    PackageVersion: ${VERSION}
    DefaultLocale: en-US
    ManifestType: version
    ManifestVersion: 1.6.0
    EOF

    cat > "${LOCAL_MANIFEST_DIR}/blacktop.ida-mcp.installer.yaml" <<EOF
    # yaml-language-server: \$schema=https://aka.ms/winget-manifest.installer.1.6.0.schema.json
    PackageIdentifier: blacktop.ida-mcp
    PackageVersion: ${VERSION}
    MinimumOSVersion: 10.0.17763.0
    InstallerType: zip
    NestedInstallerType: portable
    NestedInstallerFiles:
      - RelativeFilePath: ida-mcp.exe
        PortableCommandAlias: ida-mcp
    Installers:
      - Architecture: x64
        InstallerUrl: https://github.com/blacktop/ida-mcp-rs/releases/download/v${VERSION}/ida-mcp_${VERSION}_Windows_x86_64.zip
        InstallerSha256: ${WIN_X86_64_HASH_UPPER}
    ManifestType: installer
    ManifestVersion: 1.6.0
    EOF

    cat > "${LOCAL_MANIFEST_DIR}/blacktop.ida-mcp.locale.en-US.yaml" <<EOF
    # yaml-language-server: \$schema=https://aka.ms/winget-manifest.defaultLocale.1.6.0.schema.json
    PackageIdentifier: blacktop.ida-mcp
    PackageVersion: ${VERSION}
    PackageLocale: en-US
    Publisher: blacktop
    PublisherUrl: https://github.com/blacktop
    PublisherSupportUrl: https://github.com/blacktop/ida-mcp-rs/issues
    PackageName: ida-mcp
    PackageUrl: https://github.com/blacktop/ida-mcp-rs
    License: MIT
    LicenseUrl: https://github.com/blacktop/ida-mcp-rs/blob/main/LICENSE
    ShortDescription: Headless IDA Pro MCP Server for AI-powered binary analysis
    InstallationNotes: |
      ida-mcp requires IDA Pro 9.x. Set the IDADIR environment variable to your IDA
      installation path (e.g. setx IDADIR "C:\Program Files\IDA Professional 9.3"),
      or add the IDA directory to your PATH.
    Tags:
      - ida
      - mcp
      - reverse-engineering
      - disassembly
      - decompiler
    ManifestType: defaultLocale
    ManifestVersion: 1.6.0
    EOF

    TMPDIR="$(mktemp -d)"
    git clone --depth 1 --sparse \
        "https://x-access-token:${GH_AUTH_TOKEN}@github.com/blacktop/winget-pkgs.git" \
        "${TMPDIR}"

    cd "${TMPDIR}"
    git sparse-checkout set "manifests/b/blacktop"
    git remote add upstream https://github.com/microsoft/winget-pkgs.git
    git fetch --depth 1 upstream master
    if git ls-remote --exit-code --heads origin "${BRANCH}" >/dev/null 2>&1; then
        git fetch origin "${BRANCH}:${BRANCH}"
        git checkout "${BRANCH}"
    else
        git checkout -b "${BRANCH}" upstream/master
    fi
    mkdir -p "${REMOTE_MANIFEST_DIR}"
    cp "${OLDPWD}/${LOCAL_MANIFEST_DIR}"/* "${REMOTE_MANIFEST_DIR}/"

    git config user.name "github-actions[bot]"
    git config user.email "github-actions[bot]@users.noreply.github.com"
    git add "${REMOTE_MANIFEST_DIR}"
    if ! git diff --cached --quiet; then
        git commit -m "New version: blacktop.ida-mcp version ${VERSION}"
        git push origin "${BRANCH}"
    fi

    export GH_TOKEN="${GH_AUTH_TOKEN}"
    if [[ -z "$(gh pr list --repo microsoft/winget-pkgs --head "blacktop:${BRANCH}" --json number --jq '.[0].number // empty')" ]]; then
        gh pr create \
            --repo microsoft/winget-pkgs \
            --head "blacktop:${BRANCH}" \
            --base master \
            --title "New version: blacktop.ida-mcp version ${VERSION}" \
            --body "### Pull request for ida-mcp v${VERSION}

        - [x] Manifest: blacktop.ida-mcp
        - [x] Version: ${VERSION}
        - [x] InstallerType: zip (portable)
        - [x] Architectures: x64

        Created automatically by [ida-mcp release automation](https://github.com/blacktop/ida-mcp-rs)."
    fi

publish-cask version revision="":
    #!/usr/bin/env bash
    set -euo pipefail
    VERSION="{{ version }}"
    IDA_VERSION="${VERSION%.*}"  # e.g. 9.3.1 -> 9.3
    REVISION="{{ revision }}"
    WORKDIR="dist/release-sync/${VERSION}"
    CHECKSUMS_FILE="${WORKDIR}/checksums.txt"
    [ -f "${CHECKSUMS_FILE}" ] || { echo "Missing ${CHECKSUMS_FILE}. Run download-checksums ${VERSION} first."; exit 1; }
    gh auth status >/dev/null
    GH_AUTH_TOKEN="$(gh auth token)"

    if [[ -n "$REVISION" ]]; then
        CASK_VERSION="${VERSION},${REVISION}"
        URL_VERSION='#{version.before_comma}'
    else
        CASK_VERSION="${VERSION}"
        URL_VERSION='#{version}'
    fi

    hash_for() { grep "$1" "${CHECKSUMS_FILE}" | awk '{print $1}'; }
    DARWIN_ARM64_SHA=$(hash_for "Darwin_arm64.tar.gz")
    DARWIN_X86_64_SHA=$(hash_for "Darwin_x86_64.tar.gz")
    LINUX_X86_64_SHA=$(hash_for "Linux_x86_64.tar.gz")

    BASE_RELEASE_URL="https://github.com/blacktop/ida-mcp-rs/releases/download/v${URL_VERSION}"

    CASK_FILE="${WORKDIR}/ida-mcp.rb"
    cat > "${CASK_FILE}" << CASK
    # This file is auto-generated. DO NOT EDIT.
    cask "ida-mcp" do
      arch arm: "arm64", intel: "x86_64"
      os macos: "Darwin", linux: "Linux"

      version "${CASK_VERSION}"
      sha256 arm:          "${DARWIN_ARM64_SHA}",
             intel:        "${DARWIN_X86_64_SHA}",
             x86_64_linux: "${LINUX_X86_64_SHA}"

      url "${BASE_RELEASE_URL}/ida-mcp_${URL_VERSION}_#{os}_#{arch}.tar.gz"
      name "ida-mcp"
      desc "Headless IDA Pro MCP Server for AI-powered binary analysis (IDA ${IDA_VERSION})"
      homepage "https://github.com/blacktop/ida-mcp-rs"

      conflicts_with cask: "ida-mcp@beta"

      binary "ida-mcp"

      on_macos do
        postflight do
          Dir.glob("#{staged_path}/**/ida-mcp").each do |f|
            system_command "/usr/bin/xattr", args: ["-dr", "com.apple.quarantine", f]
          end
        end
      end

      caveats do
        <<~EOS
          ida-mcp requires IDA Pro ${IDA_VERSION} to be installed.
          For other IDA versions: brew install blacktop/tap/ida-mcp@<version>

          Standard IDA installations work automatically:
            claude mcp add ida -- ida-mcp

          If using a non-standard path:
            macOS: set DYLD_LIBRARY_PATH to your IDA path
            Linux: set IDADIR or LD_LIBRARY_PATH to your IDA path
        EOS
      end
    end
    CASK

    TMPDIR="$(mktemp -d)"
    git clone "https://x-access-token:${GH_AUTH_TOKEN}@github.com/blacktop/homebrew-tap.git" "${TMPDIR}"
    cp "${CASK_FILE}" "${TMPDIR}/Casks/ida-mcp.rb"

    cd "${TMPDIR}"
    git config user.name "github-actions[bot]"
    git config user.email "github-actions[bot]@users.noreply.github.com"
    git add "Casks/ida-mcp.rb"
    git diff --cached --quiet || git commit -m "Update ida-mcp to ${CASK_VERSION} (IDA ${IDA_VERSION})"
    git push

publish-beta-cask version ida_version="9.4":
    #!/usr/bin/env bash
    set -euo pipefail
    VERSION="{{ version }}"
    IDA_VERSION="{{ ida_version }}"
    WORKDIR="dist/release-sync/${VERSION}"
    gh auth status >/dev/null
    GH_AUTH_TOKEN="$(gh auth token)"

    # Beta uses only Darwin arm64 tarball
    TARBALL_URL="https://github.com/blacktop/ida-mcp-rs/releases/download/v${VERSION}/ida-mcp_${VERSION}_Darwin_arm64.tar.gz"
    mkdir -p "${WORKDIR}"
    curl -sL "${TARBALL_URL}" -o "${WORKDIR}/ida-mcp_${VERSION}_Darwin_arm64.tar.gz"
    SHA256=$(shasum -a 256 "${WORKDIR}/ida-mcp_${VERSION}_Darwin_arm64.tar.gz" | awk '{print $1}')

    CASK_FILE="${WORKDIR}/ida-mcp@beta.rb"
    cat > "${CASK_FILE}" << EOF
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
          ida-mcp@beta requires IDA Pro ${IDA_VERSION}+ to be installed.
          This is a prerelease version for testing.

          Standard IDA installations work automatically:
            claude mcp add ida -- ida-mcp

          If using a non-standard path, set DYLD_LIBRARY_PATH:
            claude mcp add ida -e DYLD_LIBRARY_PATH='/path/to/ida/Contents/MacOS' -- ida-mcp
        EOS
      end
    end
    EOF

    TMPDIR="$(mktemp -d)"
    git clone "https://x-access-token:${GH_AUTH_TOKEN}@github.com/blacktop/homebrew-tap.git" "${TMPDIR}"
    cp "${CASK_FILE}" "${TMPDIR}/Casks/ida-mcp@beta.rb"

    cd "${TMPDIR}"
    git config user.name "github-actions[bot]"
    git config user.email "github-actions[bot]@users.noreply.github.com"
    git add "Casks/ida-mcp@beta.rb"
    git diff --cached --quiet || git commit -m "Update ida-mcp@beta to ${VERSION}"
    git push

publish-versioned-cask version ida_version:
    #!/usr/bin/env bash
    set -euo pipefail
    VERSION="{{ version }}"
    IDA_VERSION="{{ ida_version }}"
    WORKDIR="dist/release-sync/${VERSION}"
    gh auth status >/dev/null
    GH_AUTH_TOKEN="$(gh auth token)"

    # Versioned casks use only Darwin arm64 (historical releases)
    TARBALL_URL="https://github.com/blacktop/ida-mcp-rs/releases/download/v${VERSION}/ida-mcp_${VERSION}_Darwin_arm64.tar.gz"
    mkdir -p "${WORKDIR}"
    curl -sL "${TARBALL_URL}" -o "${WORKDIR}/ida-mcp_${VERSION}_Darwin_arm64.tar.gz"
    SHA256=$(shasum -a 256 "${WORKDIR}/ida-mcp_${VERSION}_Darwin_arm64.tar.gz" | awk '{print $1}')

    CASK_FILE="${WORKDIR}/ida-mcp@${IDA_VERSION}.rb"
    cat > "${CASK_FILE}" << CASK
    # This file is auto-generated. DO NOT EDIT.
    cask "ida-mcp@${IDA_VERSION}" do
      version "${VERSION}"
      sha256 "${SHA256}"

      url "https://github.com/blacktop/ida-mcp-rs/releases/download/v#{version}/ida-mcp_#{version}_Darwin_arm64.tar.gz"
      name "ida-mcp (IDA ${IDA_VERSION})"
      desc "Headless IDA Pro MCP Server for AI-powered binary analysis (IDA ${IDA_VERSION})"
      homepage "https://github.com/blacktop/ida-mcp-rs"

      binary "ida-mcp"

      postflight do
        Dir.glob("#{staged_path}/**/ida-mcp").each do |f|
          system_command "/usr/bin/xattr", args: ["-dr", "com.apple.quarantine", f]
        end
      end

      caveats do
        <<~EOS
          ida-mcp@${IDA_VERSION} requires IDA Pro ${IDA_VERSION} to be installed.

          Standard IDA installations work automatically:
            claude mcp add ida -- ida-mcp

          If using a non-standard path, set DYLD_LIBRARY_PATH:
            claude mcp add ida -e DYLD_LIBRARY_PATH='/path/to/ida/Contents/MacOS' -- ida-mcp
        EOS
      end
    end
    CASK

    TMPDIR="$(mktemp -d)"
    git clone "https://x-access-token:${GH_AUTH_TOKEN}@github.com/blacktop/homebrew-tap.git" "${TMPDIR}"
    cp "${CASK_FILE}" "${TMPDIR}/Casks/ida-mcp@${IDA_VERSION}.rb"

    cd "${TMPDIR}"
    git config user.name "github-actions[bot]"
    git config user.email "github-actions[bot]@users.noreply.github.com"
    git add "Casks/ida-mcp@${IDA_VERSION}.rb"
    git diff --cached --quiet || git commit -m "Update ida-mcp@${IDA_VERSION} to ${VERSION}"
    git push
