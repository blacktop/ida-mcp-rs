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

    package_linux_tar() {
        local source_dir="$1"
        local archive_name="$2"
        local package_dir
        package_dir="$(mktemp -d)"

        cp "${source_dir}/ida-mcp" "${package_dir}/ida-mcp-bin"
        chmod +x "${package_dir}/ida-mcp-bin"

        printf '%s\n' \
            '#!/bin/sh' \
            'set -eu' \
            '' \
            'source_path=$0' \
            'while [ -L "$source_path" ]; do' \
            '    source_dir=$(CDPATH= cd -- "$(dirname -- "$source_path")" && pwd)' \
            '    target=$(readlink "$source_path")' \
            '    case "$target" in' \
            '        /*) source_path=$target ;;' \
            '        *) source_path="${source_dir}/${target}" ;;' \
            '    esac' \
            'done' \
            'bin_dir=$(CDPATH= cd -- "$(dirname -- "$source_path")" && pwd)' \
            '' \
            'ida_dir="${IDADIR:-}"' \
            'runtime_home="${SNAP_REAL_HOME:-${HOME:-}}"' \
            'if [ -z "$ida_dir" ] && [ -n "$runtime_home" ]; then' \
            '    ida_dir="${runtime_home}/ida-pro-9.4"' \
            'fi' \
            'if [ -n "$ida_dir" ]; then' \
            '    export LD_LIBRARY_PATH="${ida_dir}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"' \
            'fi' \
            '' \
            '# Snap strict confinement remaps $HOME; point IDA at the real .idapro' \
            'if [ -n "${SNAP_REAL_HOME:-}" ]; then' \
            '    export IDAUSR="${SNAP_REAL_HOME}/.idapro"' \
            'fi' \
            '' \
            'exec "${bin_dir}/ida-mcp-bin" "$@"' \
            > "${package_dir}/ida-mcp"
        chmod +x "${package_dir}/ida-mcp"

        tar -czvf "${archive_name}" \
            -C "${package_dir}" ida-mcp ida-mcp-bin \
            -C "${GITHUB_WORKSPACE}" README.md LICENSE

        rm -rf "${package_dir}"
    }

    package_zip() {
        local source_dir="$1"
        local archive_name="$2"
        zip "${archive_name}" \
            "${source_dir}/ida-mcp.exe" \
            -j "${GITHUB_WORKSPACE}/README.md" \
            -j "${GITHUB_WORKSPACE}/LICENSE"
    }

    package_linux_tar ida-mcp-linux-x86_64 "ida-mcp_${VERSION}_Linux_x86_64.tar.gz"
    package_linux_tar ida-mcp-linux-arm64 "ida-mcp_${VERSION}_Linux_arm64.tar.gz"
    package_tar ida-mcp-macos-x86_64 "ida-mcp_${VERSION}_Darwin_x86_64.tar.gz"
    package_tar ida-mcp-macos-arm64 "ida-mcp_${VERSION}_Darwin_arm64.tar.gz"
    package_zip ida-mcp-windows-x86_64 "ida-mcp_${VERSION}_Windows_x86_64.zip"
    package_zip ida-mcp-windows-arm64 "ida-mcp_${VERSION}_Windows_arm64.zip"

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
    WIN_ARM64_HASH=$(hash_for "Windows_arm64.zip")
    python3 "{{ justfile_directory() }}/scripts/gen-scoop-manifest.py" \
      "${VERSION}" "${WIN_X86_64_HASH}" "${WIN_ARM64_HASH}" \
      > "${WORKDIR}/ida-mcp.json"

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

    lookup_hash() { awk -v a="$1" 'substr($2, length($2)-length(a)+1) == a { print $1; exit }' "${CHECKSUMS_FILE}"; }
    required_hash_for() {
        local hash
        hash=$(lookup_hash "$1")
        [[ -n "${hash}" ]] || {
            echo "Missing checksum for $1 in ${CHECKSUMS_FILE}" >&2
            exit 1
        }
        printf '%s' "${hash}"
    }
    optional_hash_for() { lookup_hash "$1"; }
    nix_sri() {
        echo -n "sha256-$(echo "$1" | xxd -r -p | base64 | tr -d '\n')"
    }

    LINUX_X86_64_SRI=$(nix_sri "$(required_hash_for "Linux_x86_64.tar.gz")")
    DARWIN_X86_64_SRI=$(nix_sri "$(required_hash_for "Darwin_x86_64.tar.gz")")
    DARWIN_ARM64_SRI=$(nix_sri "$(required_hash_for "Darwin_arm64.tar.gz")")
    # arm64-linux asset first ships in v9.3.10; older releases lack it
    LINUX_ARM64_HASH=$(optional_hash_for "Linux_arm64.tar.gz")
    if [[ -n "${LINUX_ARM64_HASH}" ]]; then
        LINUX_ARM64_SRI=$(nix_sri "${LINUX_ARM64_HASH}")
    fi

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
        aarch64-linux = {
          url = "https://github.com/blacktop/ida-mcp-rs/releases/download/vVERSION_PLACEHOLDER/ida-mcp_VERSION_PLACEHOLDER_Linux_arm64.tar.gz";
          hash = "LINUX_ARM64_HASH_PLACEHOLDER";
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
        if [ -f ./ida-mcp-bin ]; then
          cp -v ./ida-mcp-bin $out/bin/ida-mcp-bin
        fi
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

    if [[ -n "${LINUX_ARM64_HASH}" ]]; then
        sed -i.bak "s|LINUX_ARM64_HASH_PLACEHOLDER|${LINUX_ARM64_SRI}|g" \
            "${WORKDIR}/ida-mcp-default.nix"
    else
        # Drop the aarch64-linux entry so meta.platforms stays accurate
        sed -i.bak '/aarch64-linux = {/,/};/d' "${WORKDIR}/ida-mcp-default.nix"
    fi
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

# Snap builds are normally automatic via build.snapcraft.io on tag push.
# This recipe is a manual fallback: it submits a remote build to Launchpad
# (works from macOS, no local LXD), waits for both arch builds, then uploads.
# Prereq: `snapcraft login` and the snap name registered to your account.
publish-snap channel="edge":
    #!/usr/bin/env bash
    set -euo pipefail
    command -v snapcraft >/dev/null || { echo "snapcraft not found; install with: brew install snapcraft" >&2; exit 1; }
    snapcraft remote-build --launchpad-accept-public-upload
    for snap in ida-mcp_*.snap; do
        snapcraft upload "${snap}" --release "{{ channel }}"
    done

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

    lookup_hash() { awk -v a="$1" 'substr($2, length($2)-length(a)+1) == a { print $1; exit }' "${CHECKSUMS_FILE}"; }
    required_hash_for() {
        local hash
        hash=$(lookup_hash "$1")
        [[ -n "${hash}" ]] || {
            echo "Missing checksum for $1 in ${CHECKSUMS_FILE}" >&2
            exit 1
        }
        printf '%s' "${hash}"
    }
    optional_hash_for() { lookup_hash "$1"; }
    DARWIN_ARM64_SHA=$(required_hash_for "Darwin_arm64.tar.gz")
    DARWIN_X86_64_SHA=$(required_hash_for "Darwin_x86_64.tar.gz")
    LINUX_X86_64_SHA=$(required_hash_for "Linux_x86_64.tar.gz")
    # arm64-linux asset first ships in v9.3.10; older releases lack it
    LINUX_ARM64_SHA=$(optional_hash_for "Linux_arm64.tar.gz")

    BASE_RELEASE_URL="https://github.com/blacktop/ida-mcp-rs/releases/download/v${URL_VERSION}"

    SHA256_LINES="sha256 arm:          \"${DARWIN_ARM64_SHA}\",
             intel:        \"${DARWIN_X86_64_SHA}\","
    if [[ -n "${LINUX_ARM64_SHA}" ]]; then
        SHA256_LINES="${SHA256_LINES}
             arm64_linux:  \"${LINUX_ARM64_SHA}\","
    fi
    SHA256_LINES="${SHA256_LINES}
             x86_64_linux: \"${LINUX_X86_64_SHA}\""

    CASK_FILE="${WORKDIR}/ida-mcp.rb"
    cat > "${CASK_FILE}" << CASK
    # This file is auto-generated. DO NOT EDIT.
    cask "ida-mcp" do
      arch arm: "arm64", intel: "x86_64"
      os macos: "Darwin", linux: "Linux"

      version "${CASK_VERSION}"
      ${SHA256_LINES}

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
