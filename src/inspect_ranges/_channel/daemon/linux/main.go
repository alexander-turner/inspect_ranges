// vsockd v3 entrypoint: AF_VSOCK listener with peer-CID gating, bounded
// connection concurrency, and listener supervision (the accept loop is
// watched and the socket recreated on failure, so recovery never needs a
// service restart).
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

type vsockConn struct{ fd int }

func (c *vsockConn) Read(p []byte) (int, error) {
	for {
		n, err := unix.Read(c.fd, p)
		if err == unix.EINTR {
			continue
		}
		if n == 0 && err == nil {
			return 0, fmt.Errorf("EOF")
		}
		if n == 0 && err != nil {
			return 0, err
		}
		if n == 0 {
			return 0, os.ErrClosed
		}
		return n, err
	}
}

func (c *vsockConn) Write(p []byte) (int, error) {
	total := 0
	for total < len(p) {
		n, err := unix.Write(c.fd, p[total:])
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

func (c *vsockConn) Close() error { return unix.Close(c.fd) }

func listen(port uint32) (int, error) {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM, 0)
	if err != nil {
		return -1, err
	}
	addr := &unix.SockaddrVM{CID: unix.VMADDR_CID_ANY, Port: port}
	if err := unix.Bind(fd, addr); err != nil {
		unix.Close(fd)
		return -1, err
	}
	if err := unix.Listen(fd, 64); err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func main() {
	port := flag.Uint("port", DefaultPort, "vsock port to listen on")
	version := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *version {
		fmt.Printf("%s protocol=%d\n", DaemonVersion, ProtocolVersion)
		return
	}

	daemon := NewDaemon()
	limiter := make(chan struct{}, MaxConnActive)

	// listener supervision: a dead accept loop recreates the socket with
	// backoff rather than requiring a service restart (the Windows wedge
	// lesson applied on every OS)
	for {
		fd, err := listen(uint32(*port))
		if err != nil {
			daemon.diag.Add("error", "listen-failed", nil, err.Error())
			fmt.Fprintf(os.Stderr, "vsockd: listen: %v (retrying)\n", err)
			time.Sleep(time.Second)
			continue
		}
		daemon.diag.Add("info", "listening", nil, fmt.Sprintf("port %d", *port))
		acceptLoop(fd, daemon, limiter)
		unix.Close(fd)
		daemon.diag.Add("error", "listener-restarted", nil, "accept loop died")
		time.Sleep(100 * time.Millisecond)
	}
}

func acceptLoop(fd int, daemon *Daemon, limiter chan struct{}) {
	consecutiveFailures := 0
	for {
		connFd, peer, err := unix.Accept(fd)
		if err != nil {
			if err == unix.EINTR || err == unix.ECONNABORTED {
				continue
			}
			consecutiveFailures++
			daemon.diag.Add("warn", "accept-failed", nil, err.Error())
			if consecutiveFailures >= 8 {
				return // supervisor recreates the listener
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		consecutiveFailures = 0
		vm, ok := peer.(*unix.SockaddrVM)
		if !ok || vm.CID != TrustedPeerCID {
			unix.Close(connFd) // only the hypervisor host may speak to us
			continue
		}
		limiter <- struct{}{}
		go func(fd int) {
			defer func() { <-limiter }()
			daemon.Serve(&vsockConn{fd: fd})
		}(connFd)
	}
}
