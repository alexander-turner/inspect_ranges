# Spike: EBS/FSR cold start — superseded, never run

*Status: **superseded (2026-10-05).** S3-only was adopted as the image-distribution baseline after the deployment design under review declined an EBS interface and analysis showed the cost is small ([image-distribution](../../inspect-ranges/image-distribution.md) §3; measured by the [s3-pull spike](../s3-pull/README.md)). The runbook and scoped policy below are kept as reference should an FSR comparison ever be wanted; the pending IAM policy request is withdrawn (it was never attached, so there is nothing to revoke). Original status: ready to run.*

*Previously: The devbox role deliberately has no EC2/EBS permissions (verified 2026-10-04: every volume/snapshot/FSR action is denied; only `DescribeInstances` is allowed), so this spike needs a temporary scoped policy attached by an operator. Everything else — scripts, measurement harness, cleanup — is in place.*

## What it measures

The designed fleet image-distribution path ([image-distribution](../../inspect-ranges/image-distribution.md) §3), currently specified from AWS documentation with no numbers of our own: bake the image cache as an EBS snapshot; fleet instances create volumes from it instead of downloading images. Volumes created from snapshots **hydrate lazily from S3** (first-touch reads pay the fetch), and **Fast Snapshot Restore** (~$0.75/hour/AZ, 1-hour minimum) removes that penalty. The spike quantifies all three states on this instance (volumes are created from the snapshot and attached here — hydration and FSR are volume properties, so no new instances are needed):

1. first-touch sequential read of a ~6 GiB cache from a fresh snapshot-backed volume **without** FSR (lazy hydration), plus a second pass (hydrated);
2. the same from a fresh volume **with** FSR enabled;
3. baseline: the same files from the local gp3 root volume with a dropped page cache.

## How to run

1. Attach the temporary policy (12 EBS-only actions, `policy.json`) from a terminal with admin credentials:
   `aws iam put-role-policy --role-name "$DEVBOX_ROLE" --policy-name ebs-fsr-spike --policy-document file://design/spikes/ebs-fsr/policy.json`
2. On the devbox: `./run.sh all` (or phase by phase: `prepare`, `snapshot`, `measure-cold`, `enable-fsr`, `measure-fsr`, `baseline`, `cleanup`). State lives in `tmp/state.env`; `cleanup` is idempotent and removes every AWS resource (volumes, snapshot, FSR) by tag.
3. Detach the policy:
   `aws iam delete-role-policy --role-name "$DEVBOX_ROLE" --policy-name ebs-fsr-spike`

Expected cost: cents for the volumes/snapshot plus ~1 hour of FSR. Expected duration: ~30–45 minutes, dominated by snapshot completion and FSR optimization waits.

## Files

- `run.sh` — resumable phase orchestrator with full cleanup
- `policy.json` — the temporary scoped policy
