#!/bin/bash
# The generic applier: realize a range purely from a realization bundle.
# Verifies every manifest digest before acting (refuses on mismatch), brings up
# the hardened range container on the bundle's own compose project, boots every
# guest per boot.json, and waits on each guest's readiness probe.
# Usage: ./apply.sh BUNDLE_DIR [PROJECT]
set -euo pipefail
cd "$(dirname "$0")"

BUNDLE="$(realpath "$1")"
PROJECT="${2:-bundle}"
export IMAGE_CACHE="${IMAGE_CACHE:-$HOME/.cache/inspect-ranges/images}"
export RANGE_IMAGE="${RANGE_IMAGE:-inspect-ranges-range:dev}"
C="python3 ../vsock-exec/host/client.py"

echo "--- verify bundle manifest (refuse on any mismatch) ---"
python3 - "$BUNDLE" <<'EOF'
import hashlib
import json
import sys
from pathlib import Path

bundle = Path(sys.argv[1])
manifest = json.loads((bundle / "manifest.json").read_text())
failures = []
for relative, meta in manifest["files"].items():
    path = bundle / relative
    if not path.is_file():
        failures.append(f"{relative}: missing")
        continue
    if hashlib.sha256(path.read_bytes()).hexdigest() != meta["sha256"]:
        failures.append(f"{relative}: sha256 mismatch")
listed = set(manifest["files"]) | {"manifest.json"}
on_disk = {str(p.relative_to(bundle)) for p in bundle.rglob("*") if p.is_file()}
for extra in sorted(on_disk - listed):
    failures.append(f"{extra}: not in manifest")
if failures:
    print("REFUSED: bundle fails verification:")
    print("\n".join(f"  {failure}" for failure in failures))
    sys.exit(2)
print(f"bundle verified: {len(manifest['files'])} files, plan {manifest['plan_sha256'][:12]}")
EOF

echo "--- range container (hardened profile from the bundle's compose project) ---"
docker build -q -t "$RANGE_IMAGE" range/ >/dev/null
docker compose --project-name "$PROJECT" --project-directory "$BUNDLE" up -d --wait

echo "--- boot guests per boot.json ---"
python3 - "$BUNDLE" <<'EOF' > /tmp/apply-guests.sh
import json
import sys
from pathlib import Path

bundle = Path(sys.argv[1])
boot = json.loads((bundle / "boot.json").read_text())
print("#!/bin/bash\nset -euxo pipefail")
for guest in boot["guests"]:
    name = guest["name"]
    print(
        f"qemu-img create -f qcow2 -F qcow2 -b /images/{guest['image_file']} "
        f"/scratch/{name}.qcow2 {guest['overlay_gb']}G"
    )
    print(
        f"cloud-localds -N /render/guests/{name}/seed/network-config "
        f"/scratch/{name}-seed.iso "
        f"/render/guests/{name}/seed/user-data /render/guests/{name}/seed/meta-data"
    )
    print(f"virsh -c qemu:///system define /render/guests/{name}/domain.xml")
    print(f"virsh -c qemu:///system start {name}")
print("virsh -c qemu:///system list")
EOF
docker compose --project-name "$PROJECT" --project-directory "$BUNDLE" exec -T range bash < /tmp/apply-guests.sh >/dev/null

echo "--- readiness: every guest's probe per boot.json ---"
for cid in $(python3 -c "
import json, sys
boot = json.load(open('$BUNDLE/boot.json'))
print(' '.join(str(g['cid']) for g in boot['guests']))"); do
  $C "$cid" wait
  $C "$cid" exec 'cloud-init status --wait >/dev/null 2>&1; echo done' >/dev/null
done
echo "range ready (applied purely from $BUNDLE)"
