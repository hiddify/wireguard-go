package conn

import (
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
	receivePaceSleep = func(time.Duration) { time.Sleep(receivePaceLate + 5*time.Millisecond) }
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
	if time.Since(started) >= receivePaceLate || other.wait != 0 {
		t.Fatal("another socket still waited while pacing is off")
	}
}
