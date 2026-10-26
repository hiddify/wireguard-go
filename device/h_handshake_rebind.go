package device

import (
	"time"
)

// A handshake that keeps failing from the same socket rarely recovers: the NAT mapping of its
// 5-tuple may have expired (after the device slept) or DPI may have flagged it, and every retry
// goes out the same way. Reopening the bind gives a new ephemeral port, a new 5-tuple (and on a
// detour, a new dial). It happens when a handshake cycle gives up, and earlier, after
// earlyRebindAttempts unanswered initiations, when the session is already dead. At most one
// rebind per RekeyAttemptTime covers both. A configured listen_port is kept.
// Ported from Leadaxe/sing-box-lx SPEC 041 (triggers 1 and 2).

const earlyRebindAttempts = 3

// sessionStale reports whether the peer has no session to lose: no current keypair, or a last
// handshake older than RejectAfterTime, past which its keys are invalid anyway.
func (peer *Peer) sessionStale() bool {
	if peer.keypairs.Current() == nil {
		return true
	}
	last := peer.lastHandshakeNano.Load()
	return last == 0 || time.Since(time.Unix(0, last)) > RejectAfterTime
}

func (peer *Peer) rebindAfterFailedHandshake(trigger string) {
	device := peer.device
	now := time.Now().UnixNano()
	last := device.net.lastHandshakeRebind.Load()
	if last != 0 && time.Duration(now-last) < RekeyAttemptTime {
		return
	}
	if !device.net.lastHandshakeRebind.CompareAndSwap(last, now) {
		return
	}
	if !device.net.rebindPending.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer device.net.rebindPending.Store(false)
		if device.isClosed() || !device.isUp() {
			return
		}
		device.net.Lock()
		oldPort := device.net.port
		device.net.port = device.net.configuredPort
		device.net.Unlock()
		err := device.BindUpdate()
		if err != nil {
			device.log.Errorf("%v - Failed to reopen bind after failed handshakes (%s): %v", peer, trigger, err)
			return
		}
		device.net.RLock()
		newPort := device.net.port
		device.net.RUnlock()
		device.log.Verbosef("%v - Reopened bind after failed handshakes (%s), port %d -> %d", peer, trigger, oldPort, newPort)
	}()
}
