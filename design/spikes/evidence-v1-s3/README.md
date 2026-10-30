# evidence-v1 battery, slice 3: the off-instance leg (real S3)

Run: `./run.sh` (shared battery flock; CID band 30200+; needs AWS credentials and the staged vendor image). `./run.sh down` tears down leftovers. S3 objects land under `s3://$INSPECT_RANGES_SCRATCH_BUCKET/inspect-ranges/spikes/evidence-v1-s3/runs/` and are removed at the end of a run; the shared scratch bucket itself stays (it is the project's designated scratch bucket, also used by the nested-virt spike; `CreateBucket` is denied to the devbox role, recorded below).

## Result (2026-10-15, devbox)

18/18 checks green, zero container residue, zero S3 residue. Highlights:

| Measurement | Value |
|---|---|
| Watermark lag (chunk landed wall time minus capture span end), 30 chunks | median 1.1 s, worst 7.6 s |
| First chunks visible on S3 | while the range was live, before any flow finished (streamed, not end-dumped) |
| Uplink outage (8 s mid-sample) | failed put attempts observed (an attempt counter, not a chunk count); affected chunks buffered; recovery flushed; seal `complete`; offline verify unbroken |
| Store-level write-once | re-put of the sealed manifest refused with a real 412 (`PreconditionFailed`) |
| Put-only client audit (scope: the sink's client) | botocore event hook on the sink's live client observed exactly one S3 operation: `PutObject`. The battery's own reads (polling, lag replay, verify) use a separate client the hook does not see; the proof is per-client, paired with the CI pin that the writer holds no read path |
| Bad credentials mid-sample | errors reported and buffered, nothing raised; `seal` refused with `SealDeliveryError` (record honestly unsealed) |
| Binding checks from a scrubbed process | no binding: internal consistency OK; correct `--expect-seal`: OK; forged digest: exit 1 (`seal-digest-mismatch`) |

The worst-lag chunk (7.6 s) is the first chunk of a stream: it waits out the capture poll interval plus the first rotation. Steady-state lag tracks the streamer's poll cadence (0.5 s here) plus one put round trip.

## Honest substitutions and IAM limitations (the devbox role)

- **Second machine.** No second machine was reachable (no SSH alias resolves from this host), so the cross-machine verify ran as a subprocess with a scrubbed environment: fresh `HOME`, minimal `PATH`, no environment inherited from the writer, credentials only via the instance role. It still executes the repository's installed `inspect-ranges` console script from the project venv, so it proves the verifier needs nothing from the writer's process, environment, or working state, not that it needs no installation; and it shares the instance role, so a true second machine (different credentials) should replace this when the fleet work lands a second host.
- **Put-only credentials.** `sts:AssumeRole` (self), `sts:GetFederationToken`, and all IAM introspection are denied to the devbox role, so no genuinely put-only credential could be minted. The put-only proof is client-layer and scoped precisely: a botocore event hook on the sink's real client records every S3 operation that client issues across the run, and the set is exactly `{PutObject}`. It says nothing about other clients in the process (the battery's own reads use a separate store client), so it is paired with the CI pins: the writer holds no read path (`test_writer_never_reads`) and the S3 sink exposes none.
- **Bucket policy.** `s3:PutBucketPolicy` (and `GetBucketPolicy`, and `CreateBucket`) are denied, so the deny-overwrite policy below is written as deployment guidance and could not be applied here. The mechanism it enforces fleet-wide (conditional-put refusal) was store-proven anyway: the bucket answers 412 on a conditional re-put today.
- **Uplink outage injection.** The outage test raises `ConnectionError` at the Python sink seam (a wrapper around the real sink), not at the socket: the live network-outage shapes (hung TCP into the connect/read timeouts, response-lost-then-412) were not exercised against real S3 here. The response-lost shape is pinned offline by the CI Stubber tests; the hung-socket shape rests on the bounded client timeouts.

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
