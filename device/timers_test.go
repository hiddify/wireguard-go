package device

import (
	"context"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
	"github.com/sagernet/wireguard-go/conn"
	"github.com/sagernet/wireguard-go/tun"
)

func TestPausedTimerNetworkRecovery(t *testing.T) {
	for _, deviceWakeFirst := range []bool{false, true} {
		name := "network-wake-first"
		if deviceWakeFirst {
			name = "device-wake-first"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				device, manager, peer := newTimerTestDevice(t)
				var fired atomic.Int32
				peer.timers.sendKeepalive = peer.NewTimer(func(*Peer) { fired.Add(1) })
				callback := manager.RegisterCallback(func(event int) {
					switch event {
					case pause.EventNetworkPause:
						_ = device.Down()
					case pause.EventNetworkWake:
						_ = device.Up()
					}
				})
				manager.DevicePause()
				peer.timers.sendKeepalive.Mod(time.Second)
				time.Sleep(time.Second)
				synctest.Wait()
				var returned atomic.Bool
				go func() {
					manager.NetworkPause()
					returned.Store(true)
				}()
				synctest.Wait()
				if !returned.Load() {
					t.Fatal("NetworkPause blocked on a paused peer timer")
				}
				if deviceWakeFirst {
					manager.DeviceWake()
					manager.NetworkWake()
				} else {
					manager.NetworkWake()
					manager.DeviceWake()
				}
				synctest.Wait()
				if fired.Load() != 0 {
					t.Fatal("stopped timer fired after the peer restarted")
				}
				peer.timers.sendKeepalive.Mod(time.Second)
				time.Sleep(time.Second)
				synctest.Wait()
				if fired.Load() != 1 {
					t.Fatal("new timer did not fire after network recovery")
				}
				manager.UnregisterCallback(callback)
			})
		})
	}
}

func TestPausedTimerStop(t *testing.T) {
	for _, operation := range []string{"down", "close", "remove-peer", "delete-timer"} {
		t.Run(operation, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				device, manager, peer := newTimerTestDevice(t)
				var fired atomic.Int32
				peer.timers.sendKeepalive = peer.NewTimer(func(*Peer) { fired.Add(1) })
				manager.DevicePause()
				peer.timers.sendKeepalive.Mod(time.Second)
				time.Sleep(time.Second)
				synctest.Wait()
				var returned atomic.Bool
				go func() {
					switch operation {
					case "down":
						_ = device.Down()
					case "close":
						device.Close()
					case "remove-peer":
						device.RemovePeer(peer.handshake.remoteStatic)
					case "delete-timer":
						peer.timers.sendKeepalive.DelSync()
					}
					returned.Store(true)
				}()
				synctest.Wait()
				if !returned.Load() {
					t.Fatalf("%s requires device wake or service context cancellation", operation)
				}
				manager.DeviceWake()
				synctest.Wait()
				if fired.Load() != 0 {
					t.Fatal("cancelled timer fired on device wake")
				}
			})
		})
	}
}

func TestPausedTimerRearm(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, manager, peer := newTimerTestDevice(t)
		var fired atomic.Int32
		peer.timers.sendKeepalive = peer.NewTimer(func(*Peer) { fired.Add(1) })
		timer := peer.timers.sendKeepalive
		manager.DevicePause()
		manager.NetworkPause()
		timer.Mod(time.Second)
		time.Sleep(time.Second)
		synctest.Wait()
		manager.DeviceWake()
		synctest.Wait()
		if fired.Load() != 0 {
			t.Fatal("timer fired while network was paused")
		}
		timer.Mod(time.Hour)
		manager.NetworkWake()
		synctest.Wait()
		if fired.Load() != 0 {
			t.Fatal("wake fired an obsolete timer expiration")
		}
		time.Sleep(time.Hour)
		synctest.Wait()
		if fired.Load() != 1 {
			t.Fatal("rearmed timer did not fire at its new deadline")
		}
		manager.DevicePause()
		timer.Mod(time.Second)
		time.Sleep(time.Second)
		synctest.Wait()
		manager.DeviceWake()
		synctest.Wait()
		if fired.Load() != 2 {
			t.Fatal("deferred timer did not fire exactly once on wake")
		}
	})
}

func TestPausedTimerDoesNotAccumulateGoroutines(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, manager, peer := newTimerTestDevice(t)
		var fired atomic.Int32
		peer.timers.sendKeepalive = peer.NewTimer(func(*Peer) { fired.Add(1) })
		manager.DevicePause()
		synctest.Wait()
		before := runtime.NumGoroutine()
		for range 200 {
			peer.timers.sendKeepalive.Mod(time.Millisecond)
			time.Sleep(time.Millisecond)
			synctest.Wait()
		}
		if growth := runtime.NumGoroutine() - before; growth > 16 {
			t.Fatalf("paused timer accumulated %d goroutines", growth)
		}
		manager.DeviceWake()
		synctest.Wait()
		if fired.Load() != 1 {
			t.Fatalf("deferred timer fired %d times, want 1", fired.Load())
		}
	})
}

func TestTimerRearmWhileCallbackRunning(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, _, peer := newTimerTestDevice(t)
		release := make(chan struct{})
		var fired atomic.Int32
		peer.timers.sendKeepalive = peer.NewTimer(func(*Peer) {
			if fired.Add(1) == 1 {
				<-release
			}
		})
		timer := peer.timers.sendKeepalive
		timer.Mod(0)
		synctest.Wait()
		timer.Mod(0)
		// Let this expiration queue behind the first callback. A mutex wait
		// is not durably blocked for synctest.Wait.
		for range 10 {
			runtime.Gosched()
		}
		timer.Mod(time.Hour)
		close(release)
		synctest.Wait()
		if fired.Load() != 1 {
			t.Fatal("an old queued callback consumed the new timer early")
		}
		time.Sleep(time.Hour)
		synctest.Wait()
		if fired.Load() != 2 {
			t.Fatal("rearmed timer did not fire at its new deadline")
		}
	})
}

func TestTimerConcurrentPauseAndReset(t *testing.T) {
	device, manager, peer := newTimerTestDevice(t)
	fired := make(chan struct{}, 1)
	peer.timers.sendKeepalive = peer.NewTimer(func(*Peer) {
		select {
		case fired <- struct{}{}:
		default:
		}
	})
	callback := manager.RegisterCallback(func(event int) {
		switch event {
		case pause.EventNetworkPause:
			_ = device.Down()
		case pause.EventNetworkWake:
			_ = device.Up()
		}
	})
	var workers sync.WaitGroup
	workers.Go(func() {
		for range 100 {
			manager.DevicePause()
			manager.NetworkPause()
			manager.NetworkWake()
			manager.DeviceWake()
		}
	})
	workers.Go(func() {
		for range 500 {
			peer.timers.sendKeepalive.Mod(0)
		}
	})
	workers.Go(func() {
		for range 500 {
			peer.timers.sendKeepalive.DelSync()
		}
	})
	workers.Wait()
	peer.timers.sendKeepalive.DelSync()
	select {
	case <-fired:
	default:
	}
	peer.timers.sendKeepalive.Mod(0)
	select {
	case <-fired:
	case <-time.After(time.Second):
		t.Fatal("timer did not recover after concurrent pause, reset and cancellation")
	}
	manager.UnregisterCallback(callback)
}

func newTimerTestDevice(t *testing.T) (*Device, pause.Manager, *Peer) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ctx = pause.WithDefaultManager(ctx)
	manager := service.FromContext[pause.Manager](ctx)
	device := NewDevice(ctx, &timerTestTUN{done: make(chan struct{}), events: make(chan tun.Event)}, &timerTestBind{}, &Logger{Verbosef: DiscardLogf, Errorf: t.Logf}, 1)
	t.Cleanup(func() {
		cancel()
		device.Close()
	})
	peer, err := device.NewPeer(NoisePublicKey{1})
	if err != nil {
		t.Fatal(err)
	}
	if err := device.Up(); err != nil {
		t.Fatal(err)
	}
	return device, manager, peer
}

type timerTestTUN struct {
	tun.Device
	done   chan struct{}
	events chan tun.Event
	once   sync.Once
}

func (*timerTestTUN) MTU() (int, error)                        { return 1408, nil }
func (*timerTestTUN) BatchSize() int                           { return 1 }
func (t *timerTestTUN) Events() <-chan tun.Event               { return t.events }
func (t *timerTestTUN) Read([][]byte, []int, int) (int, error) { <-t.done; return 0, net.ErrClosed }
func (t *timerTestTUN) Close() error {
	t.once.Do(func() { close(t.done); close(t.events) })
	return nil
}

type timerTestBind struct{ conn.Bind }

func (*timerTestBind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) { return nil, 12345, nil }
func (*timerTestBind) Close() error                                    { return nil }
func (*timerTestBind) BatchSize() int                                  { return 1 }
