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
// Measured, CPU seconds for a gigabyte downloaded through a WireGuard endpoint, without and with
// it: on macOS 17 to 26 and 9 (and 260 to 270 Mbit/s where it had been 170 to 265), behind
// another tunnel, whose packets arrive one at a time, 44 and 13; on Linux, in two runs on a
// shared server, 26 and 19, and 61 and 34.
const (
	receivePaceFrom    = 4000                   // datagrams a second from which receives are paced
	receivePaceBatch   = 24                     // datagrams a paced receive aims to find waiting
	receivePaceMinWait = 250 * time.Microsecond // the shortest wait worth a timer
	receivePaceMaxWait = time.Millisecond       // the longest: what a busy tunnel's packets may be late by
	receivePaceWindow  = 25 * time.Millisecond  // the rate is measured over this long
	receivePaceLate    = 20 * time.Millisecond  // a wait that took this long was not kept by the system
	receivePaceOffFor  = 30 * time.Second       // how long pacing stays off after waits that came late
	receivePaceLateMax = 3                      // late waits in a row before it goes off
)

// receivePacingOff is when pacing may be used again (unix nanoseconds), after the system let its
// waits run late: with timers held back, each short wait would be a long one.
var receivePacingOff atomic.Int64

// receivePacingDisabled turns it off for good: HIDDIFY_NO_READ_PACE=1, to compare with and without.
var receivePacingDisabled = os.Getenv("HIDDIFY_NO_READ_PACE") == "1"

// receivePaceSleep is the wait; a test makes it late.
var receivePaceSleep = time.Sleep

// receivePace is the pacing of one socket's receives. Only the goroutine that receives uses it.
type receivePace struct {
	start   time.Time     // of the window the rate is measured over
	packets int           // received in it
	wait    time.Duration // before a receive from the empty socket; 0 while the tunnel is not busy
	drained bool          // the last receive took everything the socket had
	late    int           // waits in a row that came late
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
	if time.Since(started) < receivePaceLate {
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
	p.start, p.packets = now, 0
	if rate < receivePaceFrom {
		p.wait = 0
		return
	}
	p.wait = min(max(time.Duration(receivePaceBatch/rate*float64(time.Second)), receivePaceMinWait), receivePaceMaxWait)
}
