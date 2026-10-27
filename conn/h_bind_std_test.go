package conn

import (
	"errors"
	"syscall"
	"testing"
)

// An IPv6 socket that cannot be opened (the interface it is bound to has no IPv6, or IPv6 is
// off) must not take down IPv4: the bind opens with IPv4 alone.
func TestH_StdNetBindToleratesIPv6Failure(t *testing.T) {
	bind := NewStdNetBind(func(network, address string, conn syscall.RawConn) error {
		if network == "udp6" {
			return errors.New("bind to interface: no IPv6 address")
		}
		return nil
	}).(*StdNetBind)
	fns, port, err := bind.Open(0)
	if err != nil {
		t.Fatalf("open failed: %v", err)
	}
	defer bind.Close()
	if port == 0 || len(fns) == 0 || bind.ipv4 == nil || bind.ipv6 != nil {
		t.Fatalf("expected an IPv4-only bind, got port %d, %d receivers, v4 %v, v6 %v", port, len(fns), bind.ipv4 != nil, bind.ipv6 != nil)
	}
}

// When IPv4 cannot be opened either, the error is still reported.
func TestH_StdNetBindFailsWithoutAnyFamily(t *testing.T) {
	bind := NewStdNetBind(func(network, address string, conn syscall.RawConn) error {
		return errors.New("bind to interface failed")
	}).(*StdNetBind)
	if _, _, err := bind.Open(0); err == nil {
		bind.Close()
		t.Fatal("open succeeded without any socket")
	}
}
