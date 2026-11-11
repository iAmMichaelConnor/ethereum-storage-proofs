#!/usr/bin/env bash
# Install the Noir compiler pinned in toolchain.json into .tools/noir, where the
# Python commands look for it unless NARGO_BIN names another nargo.
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ "$(uname -s)-$(uname -m)" != Linux-x86_64 ]]; then
  echo 'Install Noir v1.0.0-rc.3 for your platform and set NARGO_BIN (see toolchain.json).' >&2
  exit 1
fi
mkdir -p .tools/noir
archive=.tools/noir-x86_64-unknown-linux-gnu.tar.gz
if [[ ! -f "$archive" ]]; then
  curl --fail --location --retry 3 'https://github.com/noir-lang/noir/releases/download/v1.0.0-rc.3/noir-x86_64-unknown-linux-gnu.tar.gz' -o "$archive"
fi
echo '5792dd962afce1eed834570f95d9f72cc4a09d45cd846d3b80b7a57392732973  .tools/noir-x86_64-unknown-linux-gnu.tar.gz' | sha256sum --check
tar -xzf "$archive" -C .tools/noir
.tools/noir/nargo --version
