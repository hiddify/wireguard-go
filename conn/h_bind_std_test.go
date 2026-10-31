package conn

import (
	"bytes"
	"errors"
	"net"
	"syscall"
	"testing"
	"time"
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

// Noise packets go out with SendWithoutModify: the WARP reserved bytes are written into
// WireGuard messages only. Written into a noise packet they broke a QUIC Initial's version and
// marked every random packet with the same three bytes as the tunnel's.
func TestH_StdNetBindSendWithoutModifyKeepsReservedBytes(t *testing.T) {
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	bind := NewStdNetBind(nil).(*StdNetBind)
	if _, _, err := bind.Open(0); err != nil {
		t.Fatal(err)
	}
	defer bind.Close()
	destination := peer.LocalAddr().(*net.UDPAddr).AddrPort()
	bind.SetReservedForEndpoint(destination, [3]byte{0x57, 0x3d, 0x35})
	endpoint, err := bind.ParseEndpoint(destination.String())
	if err != nil {
		t.Fatal(err)
	}
	receive := func() []byte {
		peer.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 64)
		n, _, err := peer.ReadFromUDP(buf)
		if err != nil {
			t.Fatal(err)
		}
		return buf[:n]
	}
	const offset = 16
	quicStart := []byte{0xce, 0x00, 0x00, 0x00, 0x01, 0x08}
	if err := bind.SendWithoutModify([][]byte{append(make([]byte, offset), quicStart...)}, endpoint, offset); err != nil {
		t.Fatal(err)
	}
	if got := receive(); !bytes.Equal(got, quicStart) {
		t.Fatalf("noise packet changed: sent %x, got %x", quicStart, got)
	}
	handshake := []byte{0x01, 0x00, 0x00, 0x00, 0xaa, 0xbb}
	if err := bind.Send([][]byte{append(make([]byte, offset), handshake...)}, endpoint, offset); err != nil {
		t.Fatal(err)
	}
	if got, want := receive(), []byte{0x01, 0x57, 0x3d, 0x35, 0xaa, 0xbb}; !bytes.Equal(got, want) {
		t.Fatalf("WireGuard message without the reserved bytes: want %x, got %x", want, got)
	}
}
