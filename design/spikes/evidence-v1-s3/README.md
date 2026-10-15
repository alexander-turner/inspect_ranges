# evidence-v1 battery, slice 3: the off-instance leg (real S3)

Run: `./run.sh` (shared battery flock; CID band 30200+; needs AWS credentials and the staged vendor image). `./run.sh down` tears down leftovers. S3 objects land under `s3://caisi-cyber-590183887456-us-east-1-an/inspect-ranges/spikes/evidence-v1-s3/runs/` and are removed at the end of a run; the shared scratch bucket itself stays (it is the project's designated scratch bucket, also used by the nested-virt spike; `CreateBucket` is denied to the devbox role, recorded below).

## Result (2026-10-15, devbox)

18/18 checks green, zero container residue, zero S3 residue. Highlights:

| Measurement | Value |
|---|---|
| Watermark lag (chunk landed wall time minus capture span end), 30 chunks | median 1.1 s, worst 7.6 s |
| First chunks visible on S3 | while the range was live, before any flow finished (streamed, not end-dumped) |
| Uplink outage (8 s mid-sample) | 12 failed puts buffered; recovery flushed; seal `complete`; offline verify unbroken |
| Store-level write-once | re-put of the sealed manifest refused with a real 412 (`PreconditionFailed`) |
| Put-only client audit | botocore event hook on the live client observed exactly one S3 operation: `PutObject` |
| Bad credentials mid-sample | errors reported and buffered, nothing raised; `seal` refused with `SealDeliveryError` (record honestly unsealed) |
| Binding checks from a scrubbed process | no binding: internal consistency OK; correct `--expect-seal`: OK; forged digest: exit 1 (`seal-digest-mismatch`) |

The worst-lag chunk (7.6 s) is the first chunk of a stream: it waits out the capture poll interval plus the first rotation. Steady-state lag tracks the streamer's poll cadence (0.5 s here) plus one put round trip.

## Honest substitutions and IAM limitations (devbox role `devbox-jj-allaire-role`)

- **Second machine.** No second machine was reachable (no SSH alias resolves from this host), so the cross-machine verify ran as a subprocess with a scrubbed environment: fresh `HOME`, minimal `PATH`, no repository state, credentials only via the instance role. That proves the verifier needs nothing from the writer's process or state, but it shares the instance role; a true second machine (different credentials) should replace this when the fleet work lands a second host.
- **Put-only credentials.** `sts:AssumeRole` (self), `sts:GetFederationToken`, and all IAM introspection are denied to the devbox role, so no genuinely put-only credential could be minted. The put-only proof is client-layer: a botocore event hook on the real client records every S3 operation issued during the full battery run, and the set is exactly `{PutObject}`. The writer's never-reads property is additionally pinned in CI (`test_writer_never_reads`, and the S3 sink exposes no read path to the writer).
- **Bucket policy.** `s3:PutBucketPolicy` (and `GetBucketPolicy`, and `CreateBucket`) are denied, so the deny-overwrite policy below is written as deployment guidance and could not be applied here. The mechanism it enforces fleet-wide (conditional-put refusal) was store-proven anyway: the bucket answers 412 on a conditional re-put today.

## Deployment guidance: deny-overwrite at the store

The sink already makes every put conditional (`IfNoneMatch: "*"`), so rewrites fail with 412 for OUR writer. To make the store refuse rewrites from ANY writer holding the credential (the property the tamper-evidence story wants from the store side), apply a bucket policy that rejects puts lacking the conditional header:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RequireConditionalWrites",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::EVIDENCE-BUCKET/EVIDENCE-PREFIX/*",
      "Condition": { "StringNotEquals": { "s3:if-none-match": "*" } }
    }
  ]
}
```

With the policy: a plain `put-object` (no header) is `AccessDenied`; a conditional put of an existing key is 412; only conditional puts of new keys succeed. Object Lock or versioning-plus-lifecycle are stricter alternatives when retention rules demand them. Without any store-side measure, the format's own guarantee still holds as scoped in the record: everything at or below the seal is tamper-evident from the location alone, and the sample-store seal digest (checked via `--expect-seal`) anchors the seal tier.

## Files

- `run.sh`: flock, doctor, golden derive, battery, container and S3 residue checks, S3 cleanup.
- `battery.py`: the 18 checks (render/up with capture, real `derive_evidence_location` to an `s3://` prefix, `sink_for_location` dispatch, lag metering, outage toggle, audit hook, seal/verify/binding, bad-credential writer).
