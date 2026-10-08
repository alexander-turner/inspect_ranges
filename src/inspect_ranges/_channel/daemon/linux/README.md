# vsockd v3 (Linux)

The in-guest control daemon: a static Go binary implementing protocol v3 (`design/inspect-ranges/channel-v1.md`, `range-channel.md`). The Python v2 daemon (`design/spikes/e2e-provider/guest/vsockd2.py`) is the behavioral reference it supersedes.

## Toolchain pin

Go **1.23.6** (linux/amd64), sha256 `9379441ea310de000f33a4dc767bd966e72ab2826270e038e78b2c53c2e7802d`, installed under `~/.local/go-toolchains/go1.23.6`:

```sh
curl -fsSL -o /tmp/go.tgz https://go.dev/dl/go1.23.6.linux-amd64.tar.gz
echo "9379441ea310de000f33a4dc767bd966e72ab2826270e038e78b2c53c2e7802d  /tmp/go.tgz" | sha256sum -c
mkdir -p ~/.local/go-toolchains && tar -C ~/.local/go-toolchains -xzf /tmp/go.tgz && mv ~/.local/go-toolchains/go ~/.local/go-toolchains/go1.23.6
```

Dependencies: standard library plus `golang.org/x/sys` only (`AF_VSOCK` syscalls).

## Build

```sh
export PATH="$HOME/.local/go-toolchains/go1.23.6/bin:$PATH"
CGO_ENABLED=0 GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o vsockd .
```

`-trimpath` plus `CGO_ENABLED=0` gives a reproducible static binary; `inspect-ranges daemon-bundle` performs this build and digests the result.

## Checks and tests

```sh
gofmt -l .          # must print nothing
go vet ./...
go test ./...       # includes the cross-codec drift guard
```

`tests/test_go_daemon.py` wraps `gofmt`/`go vet`/`go test` so the Python suite drives them; it skips with a notice when no pinned toolchain is on PATH or at the install path above. CI must provide the pinned toolchain so the drift guard is enforced, not skipped.

## Known containment edge: setsid escape

The command budget kills the PROCESS GROUP (TERM, then KILL after the grace). A descendant that calls `setsid()` leaves the group and survives the kill (the battery's own hostile shim is started exactly this way). `cmd.WaitDelay` bounds the daemon's pipe wait so the escape cannot hang a serve slot, and the ETIME message states the kill was group-scoped, but the surviving process is real. The honest fix is cgroup-scoped kill, recorded in `design/inspect-ranges/channel-v1.md` as future work; range containment does not rest on this kill (the hypervisor boundary does).

## At-most-once under eviction (ESTALE)

Durable results are held in a bounded FIFO until acked. An evicted-unacked id leaves a tombstone (own FIFO, 4096): polls and resends for it answer errno `ESTALE` ("executed, result lost"), and the client surfaces that as an infrastructure failure, never a re-run.

The drift guard (`wire_test.go`) decodes every vector in `tests/wire_vectors/v3.json` from its pinned frame bytes and re-encodes to byte equality, so the Go and Python codecs cannot diverge silently. Regenerating the vectors is a protocol change and needs the matching review.
