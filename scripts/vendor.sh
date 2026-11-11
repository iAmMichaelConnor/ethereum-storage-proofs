#!/usr/bin/env bash
# Rebuild vendor/keccak256 from the pinned commit of its upstream repository,
# or with --check fail if the committed copy differs. The copy keeps
# Nargo.toml, README.md, LICENSE and src/.
# Needs git and network access to github.com.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
check=false
[[ "${1:-}" == "--check" ]] && check=true

# name | repository | commit
vendored=(
    "keccak256|https://github.com/noir-lang/keccak256|cce7f909fe481dd01ef0f0501510964aef917e68"
)

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
status=0

for entry in "${vendored[@]}"; do
    IFS='|' read -r name repository commit <<< "$entry"
    clone="$scratch/$name"
    git init -q "$clone"
    git -C "$clone" fetch -q --depth 1 "$repository" "$commit"
    git -C "$clone" checkout -q FETCH_HEAD

    out="$scratch/out/$name"
    mkdir -p "$out"
    for file in Nargo.toml README.md LICENSE src; do
        if [[ -e "$clone/$file" ]]; then cp -r "$clone/$file" "$out/"; fi
    done

    if $check; then
        if ! diff -r "$out" "$root/vendor/$name" > "$scratch/$name.diff"; then
            echo "vendor/$name differs from $repository at $commit:" >&2
            cat "$scratch/$name.diff" >&2
            status=1
        fi
    else
        mkdir -p "$root/vendor"
        rm -rf "$root/vendor/$name"
        cp -r "$out" "$root/vendor/$name"
    fi
done

if $check && [[ $status -eq 0 ]]; then echo "vendor: up to date"; fi
exit $status
