#!/usr/bin/env bash
#
# Checks this tree and packs the archive a subscriber receives.
#
# Nothing is baked in any more. The archive used to carry a node endpoint, which meant reissuing it
# every time a node moved and left a subscriber pointed at one that had gone away seeing a failure
# that read like a credential problem. The address is an argument to `connect` now, so one archive
# serves every node and cannot go stale.
#
# There is no certificate fingerprint either — the node authenticates itself with the subscriber's
# key during the handshake, so its certificate carries no trust and may be rotated freely — and no
# compression dictionary, since the node hands its own over while connecting.
#
#   ./provision.sh
#
# The name is kept because that is what the release notes and the muscle memory say.

set -euo pipefail

cd "$(dirname "$0")"

output="$HOME/manka-shreds-sdk.zip"

while [ $# -gt 0 ]; do
    case "$1" in
        --output)   output="$2"; shift 2 ;;
        --endpoint)
            echo "--endpoint is no longer used: the address is an argument to connect(), so one" >&2
            echo "archive serves every node. Pass host:port at the call site instead." >&2
            exit 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

# ---- prove it before shipping it ----------------------------------------------------------------

echo "checking the tree..."
( cd rust && cargo test --quiet ) || { echo "the Rust SDK does not pass its own tests" >&2; exit 1; }
( cd typescript && npm test --silent >/dev/null 2>&1 ) \
    || { echo "the TypeScript SDK does not pass its own tests" >&2; exit 1; }

# Neither SDK may carry an address. Both suites already assert this, but a packing step that shipped
# one anyway is exactly the failure this script exists to prevent, so it is checked here too.
for stale in rust/src/defaults.rs typescript/src/defaults.ts; do
    if [ -e "$stale" ]; then
        echo "$stale is back; the address is an argument to connect(), not a build-time constant" >&2
        exit 1
    fi
done

# ---- pack ---------------------------------------------------------------------------------------
#
# Build artefacts are excluded rather than cleaned, so packing does not throw away a working target
# directory.

rm -f "$output"
zip -qr "$output" . \
    -x '*/target/*' '*/node_modules/*' '*/dist/*' '*/dist-test/*' \
       '.git/*' '*/.git/*' '*.zip' 'provision.sh'

echo
echo "packed $output ($(du -h "$output" | cut -f1))"
unzip -l "$output" | tail -1
echo
echo "Check the node is on a build that speaks the current handshake before handing this out. An"
echo "archive meeting a node that predates it fails at connect, and reads to the subscriber like a"
echo "bad credential rather than a version mismatch."
