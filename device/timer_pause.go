package device

import (
	"context"
	"sync"

	"github.com/sagernet/sing/service/pause"
)

// timerPauseManager defers expired timers without keeping their callbacks (or
// runningLock) alive. In particular, a pause callback can stop peers while
// holding the pause manager's lock without waiting for a future wake event.
type timerPauseManager struct {
	ctx        context.Context
	pause      pause.Manager
	access     sync.Mutex
	pending    map[*Timer]uint64
	stopped    bool
	changed    chan struct{}
	done       chan struct{}
	closed     chan struct{}
	unregister func()
	closeOnce  sync.Once
}

func newTimerPauseManager(ctx context.Context, manager pause.Manager) *timerPauseManager {
	if manager == nil {
		return nil
	}
	m := &timerPauseManager{
		ctx:     ctx,
		pause:   manager,
		pending: make(map[*Timer]uint64),
		changed: make(chan struct{}, 1),
		done:    make(chan struct{}),
		closed:  make(chan struct{}),
	}
	callback := manager.RegisterCallback(func(int) {
		// Pause callbacks run under the shared pause manager's lock. Never
		// take a timer or device lock here.
		select {
		case m.changed <- struct{}{}:
		default:
		}
	})
	m.unregister = func() { manager.UnregisterCallback(callback) }
	go m.run()
	return m
}

func (m *timerPauseManager) isPaused() bool {
	// The channel-based IsPaused is not synchronized with pause transitions.
	return m.pause.IsDevicePaused() || m.pause.IsNetworkPaused()
}

// Called with timer.modifyingLock held. The reverse lock order is forbidden:
// resumeTimers releases access before touching individual timers.
func (m *timerPauseManager) deferTimer(timer *Timer, generation uint64) bool {
	if m == nil {
		return false
	}
	m.access.Lock()
	defer m.access.Unlock()
	if m.stopped || m.ctx.Err() != nil {
		return true
	}
	select {
	case <-m.done:
		return true
	default:
	}
	// Check while holding access so a wake cannot drain the queue between
	// observing the paused state and adding this expiration.
	if !m.isPaused() {
		return false
	}
	m.pending[timer] = generation
	return true
}

func (m *timerPauseManager) forgetTimer(timer *Timer) {
	if m == nil {
		return
	}
	m.access.Lock()
	delete(m.pending, timer)
	m.access.Unlock()
}

func (m *timerPauseManager) resumeTimers() {
	m.access.Lock()
	if m.isPaused() || len(m.pending) == 0 {
		m.access.Unlock()
		return
	}
	pending := m.pending
	m.pending = make(map[*Timer]uint64)
	m.access.Unlock()
	for timer, generation := range pending {
		timer.resume(generation)
	}
}

func (m *timerPauseManager) run() {
	defer func() {
		m.access.Lock()
		m.stopped = true
		clear(m.pending)
		m.access.Unlock()
		close(m.closed)
	}()
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-m.done:
			return
		case <-m.changed:
			m.resumeTimers()
		}
	}
}

func (m *timerPauseManager) Close() {
	if m == nil {
		return
	}
	m.closeOnce.Do(func() {
		close(m.done)
		m.unregister()
		<-m.closed
	})
}
