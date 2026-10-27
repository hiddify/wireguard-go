package device

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/wireguard-go/conn"
	"github.com/sagernet/wireguard-go/tun"
)

// hPortBind records the port each Open asks for and hands out a new port each time, like an
// ephemeral UDP socket.
type hPortBind struct {
	conn.Bind
	access sync.Mutex
	asked  []uint16
	next   uint16
}

func (b *hPortBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.access.Lock()
	defer b.access.Unlock()
	b.asked = append(b.asked, port)
	if port != 0 {
		return nil, port, nil
	}
	b.next++
	return nil, 40000 + b.next, nil
}

func (b *hPortBind) Close() error         { return nil }
func (b *hPortBind) BatchSize() int       { return 1 }
func (b *hPortBind) SetMark(uint32) error { return nil }

func (b *hPortBind) opens() []uint16 {
	b.access.Lock()
	defer b.access.Unlock()
	return append([]uint16(nil), b.asked...)
}

func hRebindDevice(t *testing.T, listenPort uint16) (*Device, *Peer, *hPortBind) {
	t.Helper()
	bind := &hPortBind{}
	device := NewDevice(context.Background(), &timerTestTUN{done: make(chan struct{}), events: make(chan tun.Event, 1)}, bind, NewLogger(LogLevelSilent, ""), 1)
	t.Cleanup(device.Close)
	if listenPort != 0 {
		if err := device.IpcSet("listen_port=" + itoa(listenPort) + "\n"); err != nil {
			t.Fatal(err)
		}
	}
	peer, err := device.NewPeer(NoisePublicKey{1})
	if err != nil {
		t.Fatal(err)
	}
	if err := device.Up(); err != nil {
		t.Fatal(err)
	}
	return device, peer, bind
}

func itoa(port uint16) string {
	const digits = "0123456789"
	if port == 0 {
		return "0"
	}
	var out []byte
	for ; port > 0; port /= 10 {
		out = append([]byte{digits[port%10]}, out...)
	}
	return string(out)
}

func hWaitOpens(t *testing.T, bind *hPortBind, count int) []uint16 {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for len(bind.opens()) < count {
		if time.Now().After(deadline) {
			t.Fatalf("expected %d opens, got %v", count, bind.opens())
		}
		time.Sleep(10 * time.Millisecond)
	}
	return bind.opens()
}

// After a handshake cycle gives up, the bind is reopened on a new ephemeral port: the old
// 5-tuple may be dead in a NAT or flagged by DPI, and retrying from it never recovers.
func TestH_HandshakeGiveUpRebindsToNewPort(t *testing.T) {
	_, peer, bind := hRebindDevice(t, 0)
	first := hWaitOpens(t, bind, 1)
	peer.timers.handshakeAttempts.Store(MaxTimerHandshakes + 1)
	expiredRetransmitHandshake(peer)
	opens := hWaitOpens(t, bind, len(first)+1)
	if opens[len(opens)-1] != 0 {
		t.Fatalf("the rebind kept the old port: %v", opens)
	}
}

// A dead session (no keypair) is rebound early, after a few unanswered initiations.
func TestH_HandshakeEarlyRebindWhenSessionDead(t *testing.T) {
	_, peer, bind := hRebindDevice(t, 0)
	first := hWaitOpens(t, bind, 1)
	peer.timers.handshakeAttempts.Store(earlyRebindAttempts - 1)
	expiredRetransmitHandshake(peer)
	hWaitOpens(t, bind, len(first)+1)
}

// A live session (a recent handshake and a keypair) is not rebound early: it may be a short
// loss, and the usual retries handle it.
func TestH_HandshakeEarlyRebindSkipsLiveSession(t *testing.T) {
	_, peer, bind := hRebindDevice(t, 0)
	first := hWaitOpens(t, bind, 1)
	peer.keypairs.Lock()
	peer.keypairs.current = &Keypair{}
	peer.keypairs.Unlock()
	peer.lastHandshakeNano.Store(time.Now().UnixNano())
	peer.timers.handshakeAttempts.Store(earlyRebindAttempts - 1)
	expiredRetransmitHandshake(peer)
	time.Sleep(200 * time.Millisecond)
	if opens := bind.opens(); len(opens) != len(first) {
		t.Fatalf("a live session was rebound: %v", opens)
	}
}

// A configured listen_port is kept: the rebind cannot change it.
func TestH_HandshakeRebindKeepsListenPort(t *testing.T) {
	_, peer, bind := hRebindDevice(t, 51820)
	first := hWaitOpens(t, bind, 1)
	peer.timers.handshakeAttempts.Store(MaxTimerHandshakes + 1)
	expiredRetransmitHandshake(peer)
	opens := hWaitOpens(t, bind, len(first)+1)
	if opens[len(opens)-1] != 51820 {
		t.Fatalf("the configured port was not kept: %v", opens)
	}
}

// One rebind per RekeyAttemptTime for all triggers: the early rebind covers the give-up of the
// same cycle.
func TestH_HandshakeRebindDebounced(t *testing.T) {
	_, peer, bind := hRebindDevice(t, 0)
	first := hWaitOpens(t, bind, 1)
	peer.timers.handshakeAttempts.Store(earlyRebindAttempts - 1)
	expiredRetransmitHandshake(peer)
	hWaitOpens(t, bind, len(first)+1)
	peer.timers.handshakeAttempts.Store(MaxTimerHandshakes + 1)
	expiredRetransmitHandshake(peer)
	time.Sleep(200 * time.Millisecond)
	if opens := bind.opens(); len(opens) != len(first)+1 {
		t.Fatalf("rebound twice in one cycle: %v", opens)
	}
}
