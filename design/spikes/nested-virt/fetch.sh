#!/bin/bash
# Phase 1 of the nested-virt spike: pull the staged artifacts onto the nested
# host and verify them against the manifest. Images land in the image cache;
# the AD checkpoint bundle lands in ~/.cache/inspect-ranges/checkpoints/ad-pair.
# Usage: ./fetch.sh
set -euo pipefail
cd "$(dirname "$0")"

IMAGE_CACHE="${IMAGE_CACHE:-$HOME/.cache/inspect-ranges/images}"
CKPT_CACHE="${CKPT_CACHE:-$HOME/.cache/inspect-ranges/checkpoints}"
S3_PREFIX="${S3_PREFIX:-s3://${INSPECT_RANGES_SCRATCH_BUCKET:?set S3_PREFIX or INSPECT_RANGES_SCRATCH_BUCKET}/inspect-ranges/spikes/nested-virt}"
STAGE=tmp/stage

mkdir -p "$STAGE" "$IMAGE_CACHE" "$CKPT_CACHE"

echo "=== pull from $S3_PREFIX ==="
time aws s3 sync "$S3_PREFIX/" "$STAGE" --no-progress

echo "=== verify against manifest ==="
python3 - "$STAGE" <<'EOF'
import hashlib
import json
import sys
from pathlib import Path

stage = Path(sys.argv[1])
manifest = json.loads((stage / "manifest.json").read_text())
failures = []
for rel, meta in manifest["files"].items():
    path = stage / rel
    if not path.is_file():
        failures.append(f"{rel}: missing")
        continue
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 22), b""):
            digest.update(chunk)
    if digest.hexdigest() != meta["sha256"]:
        failures.append(f"{rel}: sha256 mismatch")
if failures:
    print("\n".join(failures))
    sys.exit(1)
print(f"all {len(manifest['files'])} files verified "
      f"(built on {manifest['built_on']}, {manifest['date']})")
EOF

echo "=== install into caches ==="
cp "$STAGE"/images/* "$IMAGE_CACHE/"
mkdir -p "$CKPT_CACHE/ad-pair"
cp "$STAGE"/checkpoints/ad-pair/* "$CKPT_CACHE/ad-pair/"
cp "$STAGE/manifest.json" "$CKPT_CACHE/ad-pair/manifest.json"

echo "OK: images in $IMAGE_CACHE, checkpoint bundle in $CKPT_CACHE/ad-pair"
