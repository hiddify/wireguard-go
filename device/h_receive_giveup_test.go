package device

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/wireguard-go/conn"
	"github.com/sagernet/wireguard-go/tun"
)

// hFailingBind's first receive function fails with a permanent error; later ones block until
// the bind closes, like a healthy socket.
type hFailingBind struct {
	conn.Bind
	access sync.Mutex
	opens  atomic.Int32
	closed chan struct{}
}

func (b *hFailingBind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.access.Lock()
	defer b.access.Unlock()
	closed := make(chan struct{})
	b.closed = closed
	if b.opens.Add(1) == 1 {
		return []conn.ReceiveFunc{func([][]byte, []int, []conn.Endpoint) (int, error) {
			return 0, errors.New("socket is gone")
		}}, 12345, nil
	}
	return []conn.ReceiveFunc{func([][]byte, []int, []conn.Endpoint) (int, error) {
		<-closed
		return 0, net.ErrClosed
	}}, 12345, nil
}

func (b *hFailingBind) Close() error {
	b.access.Lock()
	defer b.access.Unlock()
	if b.closed != nil {
		close(b.closed)
		b.closed = nil
	}
	return nil
}

func (*hFailingBind) BatchSize() int       { return 1 }
func (*hFailingBind) SetMark(uint32) error { return nil }

// A receive routine that gives up on its socket must reopen the bind, or the tunnel stops
// receiving for good until the network changes.
func TestH_ReceiveGiveUpReopensBind(t *testing.T) {
	tunDevice := &timerTestTUN{done: make(chan struct{}), events: make(chan tun.Event, 1)}
	bind := &hFailingBind{}
	device := NewDevice(context.Background(), tunDevice, bind, NewLogger(LogLevelSilent, ""), 1)
	defer device.Close()
	if err := device.Up(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for bind.opens.Load() < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("the bind was not reopened after the receive routine gave up (opens: %d)", bind.opens.Load())
		}
		time.Sleep(20 * time.Millisecond)
	}
}
