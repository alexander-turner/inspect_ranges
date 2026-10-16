// Regression pin for quality-review finding A1: every daemon socket is
// close-on-exec, so exec'd children can neither hijack the listener nor hold
// a connection open past the daemon's close. AF_VSOCK is unavailable in CI,
// so the pin exercises the production helpers over AF_INET loopback: the
// CLOEXEC flag is applied by streamSocket/acceptConn, not by the family.
package main

import (
	"net"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

func assertCloexec(t *testing.T, fd int, what string) {
	t.Helper()
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if err != nil {
		t.Fatalf("%s F_GETFD: %v", what, err)
	}
	if flags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("%s is inheritable: FD_CLOEXEC missing (finding A1 regressed)", what)
	}
}

func TestDaemonSocketsAreCloexec(t *testing.T) {
	fd, err := streamSocket(unix.AF_INET)
	if err != nil {
		t.Fatalf("streamSocket: %v", err)
	}
	defer unix.Close(fd)
	assertCloexec(t, fd, "listener")

	addr := &unix.SockaddrInet4{Port: 0, Addr: [4]byte{127, 0, 0, 1}}
	if err := unix.Bind(fd, addr); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if err := unix.Listen(fd, 1); err != nil {
		t.Fatalf("listen: %v", err)
	}
	bound, err := unix.Getsockname(fd)
	if err != nil {
		t.Fatalf("getsockname: %v", err)
	}
	port := bound.(*unix.SockaddrInet4).Port

	client, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	connFd, _, err := acceptConn(fd)
	if err != nil {
		t.Fatalf("acceptConn: %v", err)
	}
	defer unix.Close(connFd)
	assertCloexec(t, connFd, "accepted connection")
}
