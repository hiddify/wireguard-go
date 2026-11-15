package conn

import (
	"os"
	"sync/atomic"
	"time"
)

// The receives of a busy tunnel are paced.
//
// The socket becomes readable with every datagram, and the receiving goroutine is woken for each
// one: a wake of its thread, a poll of the kernel and a receive call that returns that one
// datagram, though the call can take 128. Behind it every packet then went through decryption,
// the network stack and its acknowledgement on its own.
//
// So once more than receivePaceFrom datagrams a second arrive, a receive that would find the
// socket empty waits a moment first and then takes all that arrived in one call. The wait is at
// most receivePaceMaxWait, only on a tunnel that is already busy, and the socket's buffer holds
// what arrives meanwhile. A tunnel that calms down is read at once again.
//
// It is used where a receive call takes many datagrams: macOS (recvmsg_x) and Linux and Android
// (recvmmsg). Elsewhere a call takes one datagram however many wait, and there is nothing to
// gather.
//
// A tunnel that sends at least as many datagrams as it receives is not paced: what it receives
// answers what it sends, the acknowledgements of an upload through it, and its sender waits for
// them. Held back, they cost an upload over loopback 13% of its speed. Neither is a tunnel so busy
// that the shortest wait would gather more than receivePaceBatchMax datagrams: its receives take
// a batch anyway.
//
// Measured, CPU seconds for a gigabyte downloaded through a WireGuard endpoint, without and with
// it: on macOS 17 to 26 and 9 (and 260 to 270 Mbit/s where it had been 170 to 265), behind
// another tunnel, whose packets arrive one at a time, 44 and 13; on Linux, in two runs on a
// shared server, 26 and 19, and 61 and 34.
const (
	receivePaceFrom     = 4000                   // datagrams a second from which receives are paced
	receivePaceBatch    = 24                     // datagrams a paced receive aims to find waiting
	receivePaceBatchMax = 64                     // and at most: what a socket buffer of the default size holds
	receivePaceMinWait  = 250 * time.Microsecond // the shortest wait worth a timer
	receivePaceMaxWait  = time.Millisecond       // the longest: what a busy tunnel's packets may be late by
	receivePaceWindow   = 25 * time.Millisecond  // the rate is measured over this long
	receivePaceSlack    = 500 * time.Microsecond // a wait that took twice as long and this much more was not kept by the system
	receivePaceOffFor   = 30 * time.Second       // how long pacing stays off after waits that came late
	receivePaceLateMax  = 3                      // late waits in a row before it goes off
)

// receivePaceCameLate reports a wait of wait that took took: the system did not keep it. A
// machine whose processors are all busy wakes a sleeper late, and then every wait costs more
// than it saves.
func receivePaceCameLate(wait time.Duration, took time.Duration) bool {
	return took > 2*wait+receivePaceSlack
}

// receivePacingOff is when pacing may be used again (unix nanoseconds), after the system let its
// waits run late: with timers held back, each short wait would be a long one.
var receivePacingOff atomic.Int64

// receivePacingDisabled turns it off for good: HIDDIFY_NO_READ_PACE=1, to compare with and without.
var receivePacingDisabled = os.Getenv("HIDDIFY_NO_READ_PACE") == "1"

// receivePaceSleep is the wait; a test makes it late.
var receivePaceSleep = time.Sleep

// receivePace is the pacing of one socket's receives. Only the goroutine that receives uses it.
type receivePace struct {
	start    time.Time     // of the window the rate is measured over
	packets  int           // received in it
	wait     time.Duration // before a receive from the empty socket; 0 while the tunnel is not paced
	drained  bool          // the last receive took everything the socket had
	late     int           // waits in a row that came late
	sent     *atomic.Int64 // datagrams the bind sent, all along; nil: not counted
	sentMark int64         // what sent was when the window began
}

// before waits for more datagrams to arrive, when the tunnel is busy and the socket was emptied.
func (p *receivePace) before() {
	if p.wait == 0 || !p.drained {
		return
	}
	started := time.Now()
	if started.UnixNano() < receivePacingOff.Load() {
		p.wait = 0
		return
	}
	receivePaceSleep(p.wait)
	if !receivePaceCameLate(p.wait, time.Since(started)) {
		p.late = 0
		return
	}
	p.late++
	if p.late >= receivePaceLateMax {
		p.late, p.wait = 0, 0
		receivePacingOff.Store(started.Add(receivePaceOffFor).UnixNano())
	}
}

// after counts the n datagrams a receive with room for capacity returned, and at the end of each
// window sets the wait from the rate.
func (p *receivePace) after(n int, capacity int) {
	p.afterRead(n, n < capacity)
}

// afterRead counts the n datagrams a receive returned, which emptied the socket or not.
func (p *receivePace) afterRead(n int, drained bool) {
	p.drained = drained
	if n <= 0 || receivePacingDisabled {
		return
	}
	now := time.Now()
	if p.start.IsZero() {
		p.start = now
	}
	p.packets += n
	elapsed := now.Sub(p.start)
	if elapsed < receivePaceWindow {
		return
	}
	rate := float64(p.packets) / elapsed.Seconds()
	received := p.packets
	p.start, p.packets = now, 0
	if p.sent != nil {
		sent := p.sent.Load()
		sentInWindow := sent - p.sentMark
		p.sentMark = sent
		if sentInWindow >= int64(received) {
			p.wait = 0 // it sends as much as it receives: what comes in answers it
			return
		}
	}
	p.wait = receiveWait(rate)
}

// receiveWait is the wait before a receive from the emptied socket of a tunnel that brings rate
// datagrams a second.
func receiveWait(rate float64) time.Duration {
	if rate < receivePaceFrom {
		return 0 // not busy
	}
	if rate*receivePaceMinWait.Seconds() > receivePaceBatchMax {
		return 0 // so busy that its receives take a batch anyway
	}
	return min(max(time.Duration(receivePaceBatch/rate*float64(time.Second)), receivePaceMinWait), receivePaceMaxWait)
}
