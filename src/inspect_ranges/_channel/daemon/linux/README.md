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

The drift guard (`wire_test.go`) decodes every vector in `tests/wire_vectors/v3.json` from its pinned frame bytes and re-encodes to byte equality, so the Go and Python codecs cannot diverge silently. Regenerating the vectors is a protocol change and needs the matching review.
