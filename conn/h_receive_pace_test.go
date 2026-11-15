package conn

import (
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

// A busy socket's receives wait for datagrams to gather; a calm one's never do.
func TestH_ReceivePaceFollowsTheRate(t *testing.T) {
	if receivePacingDisabled {
		t.Skip("pacing is off")
	}
	var pace receivePace
	// 20,000 datagrams a second, one at a receive: the wait is set once a window has passed
	deadline := time.Now().Add(3 * receivePaceWindow)
	for time.Now().Before(deadline) {
		pace.after(1, 128)
		time.Sleep(50 * time.Microsecond)
	}
	if pace.wait < receivePaceMinWait || pace.wait > receivePaceMaxWait {
		t.Fatalf("a busy socket's wait is %v, want between %v and %v", pace.wait, receivePaceMinWait, receivePaceMaxWait)
	}
	if !pace.drained {
		t.Fatal("a receive that returned less than it had room for emptied the socket")
	}
	// a full receive left datagrams behind: the next one does not wait
	pace.after(128, 128)
	if pace.drained {
		t.Fatal("a receive that filled its room did not empty the socket")
	}
	started := time.Now()
	pace.before()
	if time.Since(started) > receivePaceMinWait/2 {
		t.Fatal("waited though datagrams were left in the socket")
	}
	// calm again: a datagram now and then
	for range 4 {
		time.Sleep(receivePaceWindow)
		pace.after(1, 128)
	}
	if pace.wait != 0 {
		t.Fatalf("a calm socket's receives wait %v", pace.wait)
	}
}

// Where the system holds timers back, a short wait turns into a long one: after a few of those
// pacing goes off for every socket, and receives return at once.
func TestH_ReceivePaceGoesOffWhenWaitsComeLate(t *testing.T) {
	defer func(sleep func(time.Duration)) { receivePaceSleep = sleep }(receivePaceSleep)
	defer receivePacingOff.Store(0)
	const late = 2*receivePaceMinWait + receivePaceSlack + 2*time.Millisecond
	receivePaceSleep = func(time.Duration) { time.Sleep(late) }
	pace := receivePace{wait: receivePaceMinWait, drained: true}
	for range receivePaceLateMax {
		pace.before()
		if pace.wait == 0 {
			break
		}
	}
	if pace.wait != 0 || receivePacingOff.Load() <= time.Now().UnixNano() {
		t.Fatal("pacing stayed on though its waits came late")
	}
	other := receivePace{wait: receivePaceMinWait, drained: true}
	started := time.Now()
	other.before()
	if time.Since(started) >= late || other.wait != 0 {
		t.Fatal("another socket still waited while pacing is off")
	}
}

// A tunnel that sends at least as many datagrams as it receives is not paced: what it receives
// answers what it sends, the acknowledgements of an upload, which its sender waits for. Held back,
// they cost an upload over loopback 13% of its speed. The same datagrams that come with nothing
// sent, a download, are paced.
func TestH_ReceivePaceLeavesAnUploadAlone(t *testing.T) {
	if receivePacingDisabled {
		t.Skip("pacing is off")
	}
	sent := new(atomic.Int64)
	pace := receivePace{sent: sent}
	deadline := time.Now().Add(3 * receivePaceWindow)
	for time.Now().Before(deadline) {
		sent.Add(2) // two data packets out for each acknowledgement in
		pace.after(1, 128)
		time.Sleep(50 * time.Microsecond)
	}
	if pace.wait != 0 {
		t.Fatalf("the acknowledgements of an upload wait %v", pace.wait)
	}
	deadline = time.Now().Add(3 * receivePaceWindow)
	for time.Now().Before(deadline) {
		pace.after(1, 128)
		time.Sleep(50 * time.Microsecond)
	}
	if pace.wait == 0 {
		t.Fatal("a download as busy is not paced")
	}
}

// A tunnel so busy that the shortest wait would gather more than a socket buffer of the default
// size holds is not paced: its receives take a batch anyway.
func TestH_ReceivePaceLeavesAVeryBusyTunnelAlone(t *testing.T) {
	if wait := receiveWait(300000); wait != 0 {
		t.Fatalf("300,000 datagrams a second wait %v", wait)
	}
	if wait := receiveWait(200000); wait != receivePaceMinWait {
		t.Fatalf("200,000 datagrams a second wait %v, want %v", wait, receivePaceMinWait)
	}
	if wait := receiveWait(48000); wait != 500*time.Microsecond {
		t.Fatalf("48,000 datagrams a second wait %v, want 500µs", wait)
	}
	if wait := receiveWait(3000); wait != 0 {
		t.Fatalf("a calm tunnel waits %v", wait)
	}
}

// The bind counts what it sends, for the pacing of its receives.
func TestH_BindCountsWhatItSends(t *testing.T) {
	bind := NewStdNetBind(nil).(*StdNetBind)
	bind.blackhole4 = true
	if err := bind.Send([][]byte{make([]byte, 100), make([]byte, 100)}, &StdNetEndpoint{AddrPort: netip.MustParseAddrPort("192.0.2.1:51820")}, 0); err != nil {
		t.Fatal(err)
	}
	if sent := bind.hSent.Load(); sent != 2 {
		t.Fatalf("%d datagrams counted, want 2", sent)
	}
}
