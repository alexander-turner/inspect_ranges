#!/bin/bash
# Phase 0 of the nested-virt spike: stage the artifacts the nested host needs
# (goldens, ISOs, the validated AD checkpoint bundle) and upload them to S3
# with a sha256 manifest. Run on the build host (m6i.metal devbox) after
# ../checkpoint-clone/run.sh has completed. Usage: ./stage.sh [upload-only]
set -euo pipefail
cd "$(dirname "$0")"

IMAGE_CACHE="${IMAGE_CACHE:-$HOME/.cache/inspect-ranges/images}"
S3_PREFIX="${S3_PREFIX:-s3://SCRATCH-BUCKET/inspect-ranges/spikes/nested-virt}"
STAGE=tmp/stage

if [[ "${1:-}" != "upload-only" ]]; then
  mkdir -p "$STAGE/images" "$STAGE/checkpoints/ad-pair"

  echo "=== copy checkpoint bundle + windows golden out of the range container ==="
  for f in dc01.xml ws01.xml dc01.mem ws01.mem dc01.qcow2 ws01.qcow2; do
    docker compose --project-directory ../checkpoint-clone cp "range:/scratch/ckpt/$f" "$STAGE/checkpoints/ad-pair/$f"
  done
  docker compose --project-directory ../checkpoint-clone cp range:/scratch/win-golden.qcow2 "$STAGE/images/win-golden.qcow2"

  echo "=== copy linux goldens + ISOs from the image cache ==="
  for f in noble-server-cloudimg-amd64.img noble-range-guest.qcow2 noble-vsockd.qcow2 noble-e2e.qcow2 \
           busybox.exe ws2022-eval.iso virtio-win.iso; do
    cp "$IMAGE_CACHE/$f" "$STAGE/images/$f"
  done

  echo "=== verify qcow2 backing references ==="
  for f in "$STAGE"/images/*.qcow2 "$STAGE"/checkpoints/ad-pair/*.qcow2; do
    echo "--- $f"
    qemu-img info --force-share "$f" | grep -E 'backing file|virtual size|disk size' || true
  done

  echo "=== manifest (sha256 + sizes + provenance) ==="
  python3 - "$STAGE" <<'EOF'
import hashlib
import json
import subprocess
import sys
from datetime import date
from pathlib import Path

stage = Path(sys.argv[1])
files = {}
for path in sorted(stage.rglob("*")):
    if not path.is_file() or path.name == "manifest.json":
        continue
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 22), b""):
            digest.update(chunk)
    files[str(path.relative_to(stage))] = {
        "sha256": digest.hexdigest(),
        "size": path.stat().st_size,
    }

instance_type = subprocess.run(
    ["bash", "-c",
     'TOKEN=$(curl -s -X PUT http://169.254.169.254/latest/api/token '
     '-H "X-aws-ec2-metadata-token-ttl-seconds: 60"); '
     'curl -s -H "X-aws-ec2-metadata-token: $TOKEN" '
     'http://169.254.169.254/latest/meta-data/instance-type'],
    capture_output=True, text=True).stdout.strip()

manifest = {
    "built_on": instance_type,
    "date": date.today().isoformat(),
    "source_spike": "checkpoint-clone",
    "cpu_model": "Skylake-Server-noTSX-IBRS",
    "notes": {
        "checkpoints/ad-pair": "overlays expect backing at /scratch/win-golden.qcow2 in the range container",
        "images/noble-*.qcow2": "relative backing on noble-server-cloudimg-amd64.img (same directory)",
    },
    "files": files,
}
(stage / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
print(json.dumps({k: v for k, v in files.items()}, indent=2))
EOF
fi

echo "=== upload to $S3_PREFIX ==="
time aws s3 sync "$STAGE" "$S3_PREFIX/" --no-progress
echo "OK: $S3_PREFIX/manifest.json"
