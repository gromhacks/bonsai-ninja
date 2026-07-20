#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: scripts/check-targets.sh [--extra] [--no-install] [target...]

Runs cargo check for representative Rust targets. With no explicit targets,
checks the six release artifact targets:

  x86_64-unknown-linux-gnu
  aarch64-unknown-linux-gnu
  x86_64-apple-darwin
  aarch64-apple-darwin
  x86_64-pc-windows-msvc
  aarch64-pc-windows-msvc

Use --extra to include the source-build smoke target:

  riscv64gc-unknown-linux-gnu

If rustup is installed, the script installs missing Rust std targets before
checking. Without rustup, the target std libraries must already be present.
EOF
}

install_targets=true
include_extra=false
targets=()

while (($# > 0)); do
    case "$1" in
        --help|-h)
            usage
            exit 0
            ;;
        --extra)
            include_extra=true
            shift
            ;;
        --no-install)
            install_targets=false
            shift
            ;;
        --)
            shift
            while (($# > 0)); do
                targets+=("$1")
                shift
            done
            ;;
        -*)
            echo "unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
        *)
            targets+=("$1")
            shift
            ;;
    esac
done

if ((${#targets[@]} == 0)); then
    targets=(
        x86_64-unknown-linux-gnu
        aarch64-unknown-linux-gnu
        x86_64-apple-darwin
        aarch64-apple-darwin
        x86_64-pc-windows-msvc
        aarch64-pc-windows-msvc
    )
fi

if [[ "$include_extra" == true ]]; then
    targets+=(riscv64gc-unknown-linux-gnu)
fi

if [[ "$install_targets" == true ]] && command -v rustup >/dev/null 2>&1; then
    rustup target add "${targets[@]}"
elif [[ "$install_targets" == true ]]; then
    echo "rustup not found; assuming requested target std libraries are already installed" >&2
fi

for target in "${targets[@]}"; do
    case "$target" in
        riscv*|powerpc*|s390x*|loongarch*|mips*|sparc*)
            if [[ -z "${TSLP_LANGUAGES:-}" ]]; then
                cat >&2 <<EOF
warning: $target is outside the release parser-download matrix.
         cargo check can still prove Rust compilation, but runtime parsing
         needs a tree-sitter-language-pack bundle for this platform or a
         build with parser sources selected by TSLP_LANGUAGES.
EOF
            fi
            ;;
    esac

    echo "==> cargo check --workspace --locked --target $target"
    cargo check --workspace --locked --target "$target"
done
