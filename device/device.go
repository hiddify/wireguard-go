/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"context"
	"errors"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
	"github.com/sagernet/wireguard-go/conn"
	"github.com/sagernet/wireguard-go/device/awg"
	"github.com/sagernet/wireguard-go/hiddify"
	"github.com/sagernet/wireguard-go/ipc"
	"github.com/sagernet/wireguard-go/ratelimiter"
	"github.com/sagernet/wireguard-go/rwcancel"
	"github.com/sagernet/wireguard-go/tun"
)

type Version uint8

const (
	VersionDefault Version = iota
	VersionAwg
	VersionAwgSpecialHandshake
)

type AtomicVersion struct {
	value atomic.Uint32
}

func NewAtomicVersion(v Version) *AtomicVersion {
	av := &AtomicVersion{}
	av.Store(v)
	return av
}

func (av *AtomicVersion) Load() Version {
	return Version(av.value.Load())
}

func (av *AtomicVersion) Store(v Version) {
	av.value.Store(uint32(v))
}

func (av *AtomicVersion) CompareAndSwap(old, new Version) bool {
	return av.value.CompareAndSwap(uint32(old), uint32(new))
}

func (av *AtomicVersion) Swap(new Version) Version {
	return Version(av.value.Swap(uint32(new)))
}

type Device struct {
	state struct {
		// state holds the device's state. It is accessed atomically.
		// Use the device.deviceState method to read it.
		// device.deviceState does not acquire the mutex, so it captures only a snapshot.
		// During state transitions, the state variable is updated before the device itself.
		// The state is thus either the current state of the device or
		// the intended future state of the device.
		// For example, while executing a call to Up, state will be deviceStateUp.
		// There is no guarantee that that intended future state of the device
		// will become the actual state; Up can fail.
		// The device can also change state multiple times between time of check and time of use.
		// Unsynchronized uses of state must therefore be advisory/best-effort only.
		state atomic.Uint32 // actually a deviceState, but typed uint32 for convenience
		// stopping blocks until all inputs to Device have been closed.
		stopping sync.WaitGroup
		// mu protects state changes.
		sync.Mutex
	}

	net struct {
		stopping sync.WaitGroup
		sync.RWMutex
		bind                conn.Bind // bind interface
		netlinkCancel       *rwcancel.RWCancel
		port                uint16 // listening port
		fwmark              uint32 // mark value (0 = disabled)
		brokenRoaming       bool
		rebindPending       atomic.Bool
		configuredPort      uint16       //H: listen_port as configured; 0 for an ephemeral port
		lastHandshakeRebind atomic.Int64 //H: unix nanoseconds of the last rebind after failed handshakes
	}

	staticIdentity struct {
		sync.RWMutex
		privateKey NoisePrivateKey
		publicKey  NoisePublicKey
	}

	peers struct {
		sync.RWMutex // protects keyMap
		keyMap       map[NoisePublicKey]*Peer
		lookupFunc   PeerLookupFunc // or nil if unused
	}

	peerStateFn        atomic.Pointer[PeerSessionStateFunc]     // observes peer session state changes, nil if unset
	priorityMsgFn      atomic.Pointer[PeerPriorityMessageFunc]  // returns a priority message to be sent around session establishment, nil if unset
	endpointResolverFn atomic.Pointer[PeerEndpointResolverFunc] // resolves candidate endpoints on handshake initiation, nil if unset

	rate struct {
		underLoadUntil atomic.Int64
		limiter        ratelimiter.Ratelimiter
	}

	allowedips    AllowedIPs
	indexTable    IndexTable
	cookieChecker CookieChecker

	pool struct {
		inboundElementsContainer  *sync.Pool
		outboundElementsContainer *sync.Pool
		messageBuffers            *WaitPool
		inboundElements           *sync.Pool
		outboundElements          *sync.Pool
	}

	queue struct {
		encryption *outboundQueue
		decryption *inboundQueue
		handshake  *handshakeQueue
	}

	tun struct {
		device tun.Device
		mtu    atomic.Int32
	}

	ipcMutex   sync.RWMutex
	closed     chan struct{}
	log        *Logger
	timerPause *timerPauseManager

	HNoise hiddify.NoiseOptions //H

	version Version
	awg     awg.Protocol
}

// deviceState represents the state of a Device.
// There are three states: down, up, closed.
// Transitions:
//
//	down -----+
//	  ↑↓      ↓
//	  up -> closed
type deviceState uint32

//go:generate go run golang.org/x/tools/cmd/stringer -type deviceState -trimprefix=deviceState
const (
	deviceStateDown deviceState = iota
	deviceStateUp
	deviceStateClosed
)

// deviceState returns device.state.state as a deviceState
// See those docs for how to interpret this value.
func (device *Device) deviceState() deviceState {
	return deviceState(device.state.state.Load())
}

// isClosed reports whether the device is closed (or is closing).
// See device.state.state comments for how to interpret this value.
func (device *Device) isClosed() bool {
	return device.deviceState() == deviceStateClosed
}

// isUp reports whether the device is up (or is attempting to come up).
// See device.state.state comments for how to interpret this value.
func (device *Device) isUp() bool {
	return device.deviceState() == deviceStateUp
}

// Must hold device.peers.Lock()
func removePeerLocked(device *Device, peer *Peer, key NoisePublicKey) {
	// stop routing and processing of packets
	device.allowedips.RemoveByPeer(peer)
	peer.Stop()

	// remove from peer map
	delete(device.peers.keyMap, key)
}

// changeState attempts to change the device state to match want.
func (device *Device) changeState(want deviceState) (err error) {
	device.state.Lock()
	defer device.state.Unlock()
	old := device.deviceState()
	if old == deviceStateClosed {
		// once closed, always closed
		device.log.Verbosef("Interface closed, ignored requested state %s", want)
		return nil
	}
	switch want {
	case old:
		return nil
	case deviceStateUp:
		device.state.state.Store(uint32(deviceStateUp))
		err = device.upLocked()
		if err == nil {
			break
		}
		fallthrough // up failed; bring the device all the way back down
	case deviceStateDown:
		device.state.state.Store(uint32(deviceStateDown))
		errDown := device.downLocked()
		if err == nil {
			err = errDown
		}
	}
	device.log.Verbosef("Interface state was %s, requested %s, now %s", old, want, device.deviceState())
	return
}

// upLocked attempts to bring the device up and reports whether it succeeded.
// The caller must hold device.state.mu and is responsible for updating device.state.state.
func (device *Device) upLocked() error {
	if err := device.BindUpdate(); err != nil {
		device.log.Errorf("Unable to update bind: %v", err)
		return err
	}

	// The IPC set operation waits for peers to be created before calling Start() on them,
	// so if there's a concurrent IPC set request happening, we should wait for it to complete.
	device.ipcMutex.Lock()
	defer device.ipcMutex.Unlock()

	// Collect peers under RLock and then release before calling into them,
	// because SendKeepalive can reach CreateMessageInitiation which acquires
	// staticIdentity.RLock; holding peers.RLock across that path would
	// invert the staticIdentity < peers hierarchy (see lock-ordering.md).
	device.peers.RLock()
	peers := make([]*Peer, 0, len(device.peers.keyMap))
	for _, peer := range device.peers.keyMap {
		peers = append(peers, peer)
	}
	device.peers.RUnlock()
	for _, peer := range peers {
		peer.Start()
		if peer.persistentKeepaliveInterval.Load() > 0 {
			peer.SendKeepalive()
		}
	}
	return nil
}

// downLocked attempts to bring the device down.
// The caller must hold device.state.mu and is responsible for updating device.state.state.
func (device *Device) downLocked() error {
	err := device.BindClose()
	if err != nil {
		device.log.Errorf("Bind close failed: %v", err)
	}

	device.peers.RLock()
	for _, peer := range device.peers.keyMap {
		peer.Stop()
	}
	device.peers.RUnlock()
	return err
}

func (device *Device) Up() error {
	return device.changeState(deviceStateUp)
}

func (device *Device) Down() error {
	return device.changeState(deviceStateDown)
}

func (device *Device) IsUnderLoad() bool {
	// check if currently under load
	now := time.Now()
	underLoad := len(device.queue.handshake.c) >= QueueHandshakeSize/8
	if underLoad {
		device.rate.underLoadUntil.Store(now.Add(UnderLoadAfterTime).UnixNano())
		return true
	}
	// check if recently under load
	return device.rate.underLoadUntil.Load() > now.UnixNano()
}

func (device *Device) SetPrivateKey(sk NoisePrivateKey) error {
	// lock required resources

	device.staticIdentity.Lock()
	defer device.staticIdentity.Unlock()

	if sk.Equals(device.staticIdentity.privateKey) {
		return nil
	}

	device.peers.Lock()
	defer device.peers.Unlock()

	lockedPeers := make([]*Peer, 0, len(device.peers.keyMap))
	for _, peer := range device.peers.keyMap {
		peer.handshake.mutex.RLock()
		lockedPeers = append(lockedPeers, peer)
	}

	// remove peers with matching public keys

	publicKey := sk.publicKey()
	for key, peer := range device.peers.keyMap {
		if peer.handshake.remoteStatic.Equals(publicKey) {
			peer.handshake.mutex.RUnlock()
			removePeerLocked(device, peer, key)
			peer.handshake.mutex.RLock()
		}
	}

	// update key material

	device.staticIdentity.privateKey = sk
	device.staticIdentity.publicKey = publicKey
	device.cookieChecker.Init(publicKey)

	// do static-static DH pre-computations

	expiredPeers := make([]*Peer, 0, len(device.peers.keyMap))
	for _, peer := range device.peers.keyMap {
		handshake := &peer.handshake
		handshake.precomputedStaticStatic, _ = device.staticIdentity.privateKey.sharedSecret(handshake.remoteStatic)
		expiredPeers = append(expiredPeers, peer)
	}

	for _, peer := range lockedPeers {
		peer.handshake.mutex.RUnlock()
	}
	for _, peer := range expiredPeers {
		peer.ExpireCurrentKeypairs()
	}

	return nil
}

func NewDevice(ctx context.Context, tunDevice tun.Device, bind conn.Bind, logger *Logger, workers int) *Device {
	device := new(Device)
	device.timerPause = newTimerPauseManager(ctx, service.FromContext[pause.Manager](ctx))
	device.state.state.Store(uint32(deviceStateDown))
	device.closed = make(chan struct{})
	device.log = logger
	device.net.bind = bind
	device.tun.device = tunDevice
	mtu, err := device.tun.device.MTU()
	if err != nil {
		device.log.Errorf("Trouble determining MTU, assuming default: %v", err)
		mtu = DefaultMTU
	}
	device.tun.mtu.Store(int32(mtu))
	device.peers.keyMap = make(map[NoisePublicKey]*Peer)
	device.rate.limiter.Init()
	device.indexTable.Init()

	device.PopulatePools()

	// create queues

	device.queue.handshake = newHandshakeQueue()
	device.queue.encryption = newOutboundQueue()
	device.queue.decryption = newInboundQueue()

	// start workers

	if workers == 0 {
		workers = runtime.NumCPU()
	}
	device.state.stopping.Wait()
	device.queue.encryption.wg.Add(workers) // One for each RoutineHandshake
	for i := 0; i < workers; i++ {
		go device.RoutineEncryption(i + 1)
		go device.RoutineDecryption(i + 1)
		go device.RoutineHandshake(i + 1)
	}

	device.state.stopping.Add(1)      // RoutineReadFromTUN
	device.queue.encryption.wg.Add(1) // RoutineReadFromTUN
	go device.RoutineReadFromTUN()
	go device.RoutineTUNEventReader()

	return device
}

// BatchSize returns the BatchSize for the device as a whole which is the max of
// the bind batch size and the tun batch size. The batch size reported by device
// is the size used to construct memory pools, and is the allowed batch size for
// the lifetime of the device.
func (device *Device) BatchSize() int {
	size := device.net.bind.BatchSize()
	dSize := device.tun.device.BatchSize()
	if size < dSize {
		size = dSize
	}
	return size
}

// AllowedIPs returns the device's allowed IPs routing table.
func (device *Device) AllowedIPs() *AllowedIPs {
	return &device.allowedips
}

// LookupPeer looks up a peer by its public key.
//
// If the peer does not exist and a [PeerLookupFunc] is set (via
// [Device.SetPeerLookupFunc]), then that function is used to create the peer
// before returning it. Peers created via this mechanism exist only until their
// state machine reaches idle, and then the peers are removed.
//
// If the peer does not exist and no [PeerLookupFunc] is set, nil is returned.
//
// Use [Device.LookupActivePeer] to only return already-existing peers, without
// using a [PeerLookupFunc].
func (device *Device) LookupPeer(pk NoisePublicKey) *Peer {
	device.peers.RLock()
	p, ok := device.peers.keyMap[pk]
	lookupFunc := device.peers.lookupFunc
	device.peers.RUnlock()
	if ok || lookupFunc == nil {
		return p
	}

	conf, ok := lookupFunc(pk)
	if !ok || conf == nil {
		return nil
	}

	p, err := device.NewPeer(pk)
	if err != nil {
		if errors.Is(err, errAddExistingPeer) {
			device.peers.RLock()
			defer device.peers.RUnlock()
			return device.peers.keyMap[pk]
		}
		device.log.Errorf("Failed to create peer: %v", err)
		return nil
	}
	p.SetAllowedIPs(conf.AllowedIPs)
	p.SetPresharedKey(conf.PresharedKey)
	p.deleteOnIdle = true
	if conf.Endpoint != nil {
		p.SetEndpointFromPacket(conf.Endpoint)
	}
	p.Start()
	return p
}

// LookupActivePeer looks up a peer by its public key.
//
// Unlike [Device.LookupPeer], this function does not use a [PeerLookupFunc] to
// create the peer if it does not already exist.
//
// If the peer does not exist or was created lazily via [PeerLookupFunc]
// and has subsequently idled away, it returns (nil, false).
func (device *Device) LookupActivePeer(pk NoisePublicKey) (_ *Peer, ok bool) {
	device.peers.RLock()
	defer device.peers.RUnlock()
	p, ok := device.peers.keyMap[pk]
	return p, ok
}

var errAddExistingPeer = errors.New("adding existing peer")

func (device *Device) RemovePeer(key NoisePublicKey) {
	device.peers.Lock()
	defer device.peers.Unlock()
	// stop peer and remove from routing

	peer, ok := device.peers.keyMap[key]
	if ok {
		removePeerLocked(device, peer, key)
	}
}

func (device *Device) RemoveAllPeers() {
	device.peers.Lock()
	defer device.peers.Unlock()

	for key, peer := range device.peers.keyMap {
		removePeerLocked(device, peer, key)
	}

	device.peers.keyMap = make(map[NoisePublicKey]*Peer)
}

// RemoveMatchingPeers removes all peers for which shouldRemove returns true.
//
// It returns the number of peers removed.
func (device *Device) RemoveMatchingPeers(shouldRemove func(NoisePublicKey) bool) (numRemoved int) {
	device.peers.Lock()
	defer device.peers.Unlock()

	for key, peer := range device.peers.keyMap {
		if shouldRemove(key) {
			removePeerLocked(device, peer, key)
			numRemoved++
		}
	}
	return numRemoved
}

// NewPeerConfig are the configuration parameters for a new peer created via a
// [PeerLookupFunc] func.
type NewPeerConfig struct {
	// AllowedIPs is the initial set of allowed IPs for the new peer.
	AllowedIPs []netip.Prefix

	// PresharedKey is the initial pre-shared key for the new peer. The zero
	// value disables the optional WireGuard pre-shared-key layer.
	PresharedKey NoisePresharedKey

	// Endpoint, if non-nil, sets the initial endpoint for newly
	// created peers.
	Endpoint conn.Endpoint
}

// PeerLookupFunc is the type of function used to look up peers by public key
// when receiving packets for unknown peers.
//
// If it returns nil, the peer is not known.
//
// Otherwise, returning non-nil signals that wireguard-go should create the peer
// with the provided allowed IPs.
//
// See [Device.SetPeerLookupFunc] and [Device.LookupPeer].
type PeerLookupFunc func(NoisePublicKey) (_ *NewPeerConfig, ok bool)

// PeerByIPPacketFunc is the type of function used to look up a peer to send to
// for a given src/dst IP pair. The ipPkt parameter is the raw IP packet being
// routed; callers needing transport-layer ports or other header fields may parse
// them from ipPkt, but must handle IP fragmentation (ports may be absent on
// non-first fragments) and protocols that do not use ports (e.g. ICMP).
//
// Except for experimental use cases, dst is the only address
// that should be relied upon when looking up a peer.
//
// If it returns ok=false, the peer is not known.
//
// See [Device.SetPeerByIPPacketFunc] and [Device.SetPeerLookupFunc].
type PeerByIPPacketFunc func(src, dst netip.Addr, ipPkt []byte) (_ NoisePublicKey, ok bool)

// PeerSessionState is the current WireGuard session state for a peer.
type PeerSessionState uint8

const (
	// PeerSessionNone means there is no handshake in progress and no session key
	// material retained for this peer.
	PeerSessionNone PeerSessionState = iota

	// PeerSessionHandshake means a handshake is in progress for this peer, but
	// there is not currently a usable WireGuard session.
	PeerSessionHandshake

	// PeerSessionEstablished means the peer has a completed WireGuard session
	// with usable session key material.
	PeerSessionEstablished

	// PeerSessionExpired means the peer's session key material is no longer
	// considered usable, but final key cleanup or lazy peer removal may not have
	// happened yet.
	PeerSessionExpired
)

// PeerSessionStateFunc is called when a peer's WireGuard session state changes.
//
// Calls are serialized per peer and delivered in that peer's transition order. The
// callback must be cheap and must not call back into Device.
type PeerSessionStateFunc func(peer NoisePublicKey, state PeerSessionState)

// SetPeerLookupFunc sets the function used to look up peers by public key
// when receiving packets for unknown peers.
func (device *Device) SetPeerLookupFunc(f PeerLookupFunc) {
	device.peers.Lock()
	defer device.peers.Unlock()
	device.peers.lookupFunc = f
}

// SetPeerByIPPacketFunc sets the function used to look up peers by IP address
// when sending packets to unknown peers.
func (device *Device) SetPeerByIPPacketFunc(f PeerByIPPacketFunc) {
	device.allowedips.mu.Lock()
	defer device.allowedips.mu.Unlock()
	device.allowedips.peerByIPPacketFunc = f
	device.allowedips.device = device
}

// SetSessionStateFunc sets the function used to observe peer WireGuard session
// state changes.
//
// It does not replay current state. Callers that need a complete view should set
// it before peers are started or lazily created, and maintain any snapshots,
// sequence numbers, and pubsub state outside wireguard-go.
//
// The callback must be concurrent-safe and must not call back into Device.
func (device *Device) SetSessionStateFunc(f PeerSessionStateFunc) {
	if f == nil {
		device.peerStateFn.Store(nil)
		return
	}
	device.peerStateFn.Store(&f)
}

// MaxPriorityMessageContentSize is the maximum size of a message returned by a
// [PeerPriorityMessageFunc]. It's a power of 2 that leaves significant space
// when accounting for all WireGuard overhead and encapsulating network protocol
// headers. Future adjustments to this value should consider all these overheads
// and any [conn.Bind] implementation limitations.
const MaxPriorityMessageContentSize = 512

// PeerPriorityMessageFunc is called when a peer's WireGuard session keypair is
// established (or re-keyed) for forward data transmission.
//
// The returned message is transmitted to the peer in priority fashion. Priority
// means it cannot be evicted from the staged packet queue by non-priority
// (read from [tun.Device]) packets. It avoids the staged queue altogether.
//
// The callback must be cheap and must not call back into [Device]. A zero length
// message or a message whose length exceeds [MaxPriorityMessageContentSize] will
// be silently dropped. Message should start with an IPv4 or IPv6 header as it
// is subject to allowed IPs lookup on the receiver, same as any other transport
// message.
type PeerPriorityMessageFunc func(peer NoisePublicKey) (msg []byte)

// SetPriorityMessageOnEstablishmentFunc sets a function to be used for sending
// a priority message around session establishment. See [PeerPriorityMessageFunc]
// docs for more details. A nil value clears any previously set value.
func (device *Device) SetPriorityMessageOnEstablishmentFunc(f PeerPriorityMessageFunc) {
	if f == nil {
		device.priorityMsgFn.Store(nil)
		return
	}
	device.priorityMsgFn.Store(&f)
}

// PeerEndpointResolverFunc is called on every handshake initiation to obtain the
// candidate endpoints for a peer. The initiation is sent to the peer's current
// endpoint and every candidate; the source of the first valid reply becomes the
// current endpoint via roaming. When it fails, the candidates from its last
// successful invocation for that peer are reused.
//
// It is called from the goroutine initiating the handshake, which blocks until
// it returns, including when the initiation originates from within [Device.IpcSet].
//
// The callback must be concurrent-safe and must not call back into [Device].
type PeerEndpointResolverFunc func(peer NoisePublicKey) ([]conn.Endpoint, error)

// SetEndpointResolverFunc sets the function used to resolve peer endpoints. See
// [PeerEndpointResolverFunc] docs for more details. A nil value clears any
// previously set value.
//
// Because it is keyed by public key rather than held per peer, it can be set
// before the peers exist. Setting it before the [Device.IpcSet] that creates
// them is the only way a peer configured without an endpoint can resolve one in
// time for the handshake initiation that same IpcSet triggers, for a peer with
// persistent keepalives on an up device.
func (device *Device) SetEndpointResolverFunc(f PeerEndpointResolverFunc) {
	if f == nil {
		device.endpointResolverFn.Store(nil)
		return
	}
	device.endpointResolverFn.Store(&f)
}

func (device *Device) Close() {
	// Unregister outside the device locks: a pause callback may call Down.
	device.timerPause.Close()
	device.state.Lock()
	defer device.state.Unlock()
	device.ipcMutex.Lock()
	defer device.ipcMutex.Unlock()
	if device.isClosed() {
		return
	}
	device.state.state.Store(uint32(deviceStateClosed))
	device.log.Verbosef("Device closing")

	device.tun.device.Close()
	device.downLocked()

	// Remove peers before closing queues,
	// because peers assume that queues are active.
	device.RemoveAllPeers()

	// We kept a reference to the encryption and decryption queues,
	// in case we started any new peers that might write to them.
	// No new peers are coming; we are done with these queues.
	device.queue.encryption.wg.Done()
	device.queue.decryption.wg.Done()
	device.queue.handshake.wg.Done()
	device.state.stopping.Wait()

	device.rate.limiter.Close()

	device.log.Verbosef("Device closed")
	close(device.closed)
}

func (device *Device) Wait() chan struct{} {
	return device.closed
}

func (device *Device) SendKeepalivesToPeersWithCurrentKeypair() {
	if !device.isUp() {
		return
	}

	// Collect the set of peers to keepalive under peers.RLock, then release
	// before invoking SendKeepalive. SendKeepalive can reach
	// CreateMessageInitiation which acquires staticIdentity.RLock; holding
	// peers.RLock across that path would invert the
	// staticIdentity < peers hierarchy (see lock-ordering.md).
	var peers []*Peer
	device.peers.RLock()
	for _, peer := range device.peers.keyMap {
		peer.keypairs.RLock()
		sendKeepalive := peer.keypairs.current != nil && sinceIncludingSleep(peer.keypairs.current.created) <= RejectAfterTime
		peer.keypairs.RUnlock()
		if sendKeepalive {
			peers = append(peers, peer)
		}
	}
	device.peers.RUnlock()
	for _, peer := range peers {
		peer.SendKeepalive()
	}
}

// closeBindLocked closes the device's net.bind.
// The caller must hold the net mutex.
func closeBindLocked(device *Device) error {
	var err error
	netc := &device.net
	if netc.netlinkCancel != nil {
		netc.netlinkCancel.Cancel()
	}
	if netc.bind != nil {
		err = netc.bind.Close()
	}
	netc.stopping.Wait()
	return err
}

func (device *Device) Bind() conn.Bind {
	device.net.Lock()
	defer device.net.Unlock()
	return device.net.bind
}

func (device *Device) BindSetMark(mark uint32) error {
	device.net.Lock()
	defer device.net.Unlock()

	// check if modified
	if device.net.fwmark == mark {
		return nil
	}

	// update fwmark on existing bind
	device.net.fwmark = mark
	if device.isUp() && device.net.bind != nil {
		if err := device.net.bind.SetMark(mark); err != nil {
			return err
		}
	}

	// clear cached source addresses
	device.peers.RLock()
	for _, peer := range device.peers.keyMap {
		peer.markEndpointSrcForClearing()
	}
	device.peers.RUnlock()

	return nil
}

// scheduleBindUpdate reopens the bind from a new goroutine: the send and
// receive paths that report conn.ErrRebindRequired run under the net read
// lock or are waited for by closeBindLocked.
func (device *Device) scheduleBindUpdate() {
	if !device.net.rebindPending.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer device.net.rebindPending.Store(false)
		err := device.BindUpdate()
		if err != nil {
			device.log.Errorf("Failed to reopen bind: %v", err)
		}
	}()
}

// scheduleBindUpdateAfter reopens the bind after delay, unless the device closes first. A
// receive routine that gives up on its socket calls it: nothing else would restart the routine,
// and the tunnel would stop receiving until the network changed. The delay keeps a socket that
// fails at once from spinning. //H
func (device *Device) scheduleBindUpdateAfter(delay time.Duration) { //H
	if !device.net.rebindPending.CompareAndSwap(false, true) { //H
		return //H
	} //H
	go func() { //H
		defer device.net.rebindPending.Store(false) //H
		select {                                    //H
		case <-time.After(delay): //H
		case <-device.closed: //H
			return //H
		} //H
		if device.isClosed() || !device.isUp() { //H
			return //H
		} //H
		device.log.Verbosef("Receive routine gave up, reopening the bind") //H
		err := device.BindUpdate()                                         //H
		if err != nil {                                                    //H
			device.log.Errorf("Failed to reopen bind: %v", err) //H
		} //H
	}() //H
} //H

func (device *Device) BindUpdate() error {
	device.net.Lock()
	defer device.net.Unlock()

	// close existing sockets
	if err := closeBindLocked(device); err != nil {
		return err
	}

	// open new sockets
	if !device.isUp() {
		return nil
	}

	// bind to new port
	var err error
	var recvFns []conn.ReceiveFunc
	netc := &device.net

	recvFns, netc.port, err = netc.bind.Open(netc.port)
	if err != nil {
		netc.port = 0
		return err
	}

	netc.netlinkCancel, err = device.startRouteListener(netc.bind)
	if err != nil {
		netc.bind.Close()
		netc.port = 0
		return err
	}

	// set fwmark
	if netc.fwmark != 0 {
		err = netc.bind.SetMark(netc.fwmark)
		if err != nil {
			return err
		}
	}

	// clear cached source addresses
	device.peers.RLock()
	for _, peer := range device.peers.keyMap {
		peer.markEndpointSrcForClearing()
	}
	device.peers.RUnlock()

	// start receiving routines
	device.net.stopping.Add(len(recvFns))
	device.queue.decryption.wg.Add(len(recvFns)) // each RoutineReceiveIncoming goroutine writes to device.queue.decryption
	device.queue.handshake.wg.Add(len(recvFns))  // each RoutineReceiveIncoming goroutine writes to device.queue.handshake
	batchSize := netc.bind.BatchSize()
	for _, fn := range recvFns {
		go device.RoutineReceiveIncoming(batchSize, fn)
	}

	device.log.Verbosef("UDP bind has been updated")
	return nil
}

func (device *Device) BindClose() error {
	device.net.Lock()
	err := closeBindLocked(device)
	device.net.Unlock()
	return err
}

func (device *Device) isAWG() bool {
	return device.version >= VersionAwg
}

func (device *Device) resetProtocol() {
	// restore default message type values
	MessageInitiationType = DefaultMessageInitiationType
	MessageResponseType = DefaultMessageResponseType
	MessageCookieReplyType = DefaultMessageCookieReplyType
	MessageTransportType = DefaultMessageTransportType
}

func (device *Device) handlePostConfig(tempAwg *awg.Protocol) error {
	if !tempAwg.ASecCfg.IsSet && !tempAwg.HandshakeHandler.IsSet {
		return nil
	}

	var errs []error

	isASecOn := false
	device.awg.ASecMux.Lock()
	if tempAwg.ASecCfg.JunkPacketCount < 0 {
		errs = append(errs, ipcErrorf(
			ipc.IpcErrorInvalid,
			"JunkPacketCount should be non negative",
		),
		)
	}
	device.awg.ASecCfg.JunkPacketCount = tempAwg.ASecCfg.JunkPacketCount
	if tempAwg.ASecCfg.JunkPacketCount != 0 {
		isASecOn = true
	}

	device.awg.ASecCfg.JunkPacketMinSize = tempAwg.ASecCfg.JunkPacketMinSize
	if tempAwg.ASecCfg.JunkPacketMinSize != 0 {
		isASecOn = true
	}

	if device.awg.ASecCfg.JunkPacketCount > 0 &&
		tempAwg.ASecCfg.JunkPacketMaxSize == tempAwg.ASecCfg.JunkPacketMinSize {

		tempAwg.ASecCfg.JunkPacketMaxSize++ // to make rand gen work
	}

	if tempAwg.ASecCfg.JunkPacketMaxSize >= MaxSegmentSize {
		device.awg.ASecCfg.JunkPacketMinSize = 0
		device.awg.ASecCfg.JunkPacketMaxSize = 1
		errs = append(errs, ipcErrorf(
			ipc.IpcErrorInvalid,
			"JunkPacketMaxSize: %d; should be smaller than maxSegmentSize: %d",
			tempAwg.ASecCfg.JunkPacketMaxSize,
			MaxSegmentSize,
		))
	} else if tempAwg.ASecCfg.JunkPacketMaxSize < tempAwg.ASecCfg.JunkPacketMinSize {
		errs = append(errs, ipcErrorf(
			ipc.IpcErrorInvalid,
			"maxSize: %d; should be greater than minSize: %d",
			tempAwg.ASecCfg.JunkPacketMaxSize,
			tempAwg.ASecCfg.JunkPacketMinSize,
		))
	} else {
		device.awg.ASecCfg.JunkPacketMaxSize = tempAwg.ASecCfg.JunkPacketMaxSize
	}

	if tempAwg.ASecCfg.JunkPacketMaxSize != 0 {
		isASecOn = true
	}

	newInitSize := MessageInitiationSize + tempAwg.ASecCfg.InitHeaderJunkSize

	if newInitSize >= MaxSegmentSize {
		errs = append(errs, ipcErrorf(
			ipc.IpcErrorInvalid,
			`init header size(148) + junkSize:%d; should be smaller than maxSegmentSize: %d`,
			tempAwg.ASecCfg.InitHeaderJunkSize,
			MaxSegmentSize,
		),
		)
	} else {
		device.awg.ASecCfg.InitHeaderJunkSize = tempAwg.ASecCfg.InitHeaderJunkSize
	}

	if tempAwg.ASecCfg.InitHeaderJunkSize != 0 {
		isASecOn = true
	}

	newResponseSize := MessageResponseSize + tempAwg.ASecCfg.ResponseHeaderJunkSize

	if newResponseSize >= MaxSegmentSize {
		errs = append(errs, ipcErrorf(
			ipc.IpcErrorInvalid,
			`response header size(92) + junkSize:%d; should be smaller than maxSegmentSize: %d`,
			tempAwg.ASecCfg.ResponseHeaderJunkSize,
			MaxSegmentSize,
		),
		)
	} else {
		device.awg.ASecCfg.ResponseHeaderJunkSize = tempAwg.ASecCfg.ResponseHeaderJunkSize
	}

	if tempAwg.ASecCfg.ResponseHeaderJunkSize != 0 {
		isASecOn = true
	}

	newCookieSize := MessageCookieReplySize + tempAwg.ASecCfg.CookieReplyHeaderJunkSize

	if newCookieSize >= MaxSegmentSize {
		errs = append(errs, ipcErrorf(
			ipc.IpcErrorInvalid,
			`cookie reply size(92) + junkSize:%d; should be smaller than maxSegmentSize: %d`,
			tempAwg.ASecCfg.CookieReplyHeaderJunkSize,
			MaxSegmentSize,
		),
		)
	} else {
		device.awg.ASecCfg.CookieReplyHeaderJunkSize = tempAwg.ASecCfg.CookieReplyHeaderJunkSize
	}

	if tempAwg.ASecCfg.CookieReplyHeaderJunkSize != 0 {
		isASecOn = true
	}

	newTransportSize := MessageTransportSize + tempAwg.ASecCfg.TransportHeaderJunkSize

	if newTransportSize >= MaxSegmentSize {
		errs = append(errs, ipcErrorf(
			ipc.IpcErrorInvalid,
			`transport size(92) + junkSize:%d; should be smaller than maxSegmentSize: %d`,
			tempAwg.ASecCfg.TransportHeaderJunkSize,
			MaxSegmentSize,
		),
		)
	} else {
		device.awg.ASecCfg.TransportHeaderJunkSize = tempAwg.ASecCfg.TransportHeaderJunkSize
	}

	if tempAwg.ASecCfg.TransportHeaderJunkSize != 0 {
		isASecOn = true
	}

	if tempAwg.ASecCfg.InitPacketMagicHeader > 4 {
		isASecOn = true
		device.log.Verbosef("UAPI: Updating init_packet_magic_header")
		device.awg.ASecCfg.InitPacketMagicHeader = tempAwg.ASecCfg.InitPacketMagicHeader
		MessageInitiationType = device.awg.ASecCfg.InitPacketMagicHeader
	} else {
		device.log.Verbosef("UAPI: Using default init type")
		MessageInitiationType = DefaultMessageInitiationType
	}

	if tempAwg.ASecCfg.ResponsePacketMagicHeader > 4 {
		isASecOn = true
		device.log.Verbosef("UAPI: Updating response_packet_magic_header")
		device.awg.ASecCfg.ResponsePacketMagicHeader = tempAwg.ASecCfg.ResponsePacketMagicHeader
		MessageResponseType = device.awg.ASecCfg.ResponsePacketMagicHeader
	} else {
		device.log.Verbosef("UAPI: Using default response type")
		MessageResponseType = DefaultMessageResponseType
	}

	if tempAwg.ASecCfg.UnderloadPacketMagicHeader > 4 {
		isASecOn = true
		device.log.Verbosef("UAPI: Updating underload_packet_magic_header")
		device.awg.ASecCfg.UnderloadPacketMagicHeader = tempAwg.ASecCfg.UnderloadPacketMagicHeader
		MessageCookieReplyType = device.awg.ASecCfg.UnderloadPacketMagicHeader
	} else {
		device.log.Verbosef("UAPI: Using default underload type")
		MessageCookieReplyType = DefaultMessageCookieReplyType
	}

	if tempAwg.ASecCfg.TransportPacketMagicHeader > 4 {
		isASecOn = true
		device.log.Verbosef("UAPI: Updating transport_packet_magic_header")
		device.awg.ASecCfg.TransportPacketMagicHeader = tempAwg.ASecCfg.TransportPacketMagicHeader
		MessageTransportType = device.awg.ASecCfg.TransportPacketMagicHeader
	} else {
		device.log.Verbosef("UAPI: Using default transport type")
		MessageTransportType = DefaultMessageTransportType
	}

	isSameHeaderMap := map[uint32]struct{}{
		MessageInitiationType:  {},
		MessageResponseType:    {},
		MessageCookieReplyType: {},
		MessageTransportType:   {},
	}

	// size will be different if same values
	if len(isSameHeaderMap) != 4 {
		errs = append(errs, ipcErrorf(
			ipc.IpcErrorInvalid,
			`magic headers should differ; got: init:%d; recv:%d; unde:%d; tran:%d`,
			MessageInitiationType,
			MessageResponseType,
			MessageCookieReplyType,
			MessageTransportType,
		),
		)
	}

	isSameSizeMap := map[int]struct{}{
		newInitSize:      {},
		newResponseSize:  {},
		newCookieSize:    {},
		newTransportSize: {},
	}

	if len(isSameSizeMap) != 4 {
		errs = append(errs, ipcErrorf(
			ipc.IpcErrorInvalid,
			`new sizes should differ; init: %d; response: %d; cookie: %d; trans: %d`,
			newInitSize,
			newResponseSize,
			newCookieSize,
			newTransportSize,
		),
		)
	} else {
		msgTypeToJunkSize = map[uint32]int{
			MessageInitiationType:  device.awg.ASecCfg.InitHeaderJunkSize,
			MessageResponseType:    device.awg.ASecCfg.ResponseHeaderJunkSize,
			MessageCookieReplyType: device.awg.ASecCfg.CookieReplyHeaderJunkSize,
			MessageTransportType:   device.awg.ASecCfg.TransportHeaderJunkSize,
		}

		packetSizeToMsgType = map[int]uint32{
			newInitSize:      MessageInitiationType,
			newResponseSize:  MessageResponseType,
			newCookieSize:    MessageCookieReplyType,
			newTransportSize: MessageTransportType,
		}
	}

	device.awg.IsASecOn.SetTo(isASecOn)
	var err error
	device.awg.JunkCreator, err = awg.NewJunkCreator(device.awg.ASecCfg)
	if err != nil {
		errs = append(errs, err)
	}

	if tempAwg.HandshakeHandler.IsSet {
		if err := tempAwg.HandshakeHandler.Validate(); err != nil {
			errs = append(errs, ipcErrorf(
				ipc.IpcErrorInvalid, "handshake handler validate: %w", err))
		} else {
			device.awg.HandshakeHandler = tempAwg.HandshakeHandler
			device.awg.HandshakeHandler.ControlledJunk.DefaultJunkCount = tempAwg.ASecCfg.JunkPacketCount
			device.awg.HandshakeHandler.SpecialJunk.DefaultJunkCount = tempAwg.ASecCfg.JunkPacketCount
			device.version = VersionAwgSpecialHandshake
		}
	} else {
		device.version = VersionAwg
	}

	device.awg.ASecMux.Unlock()

	return errors.Join(errs...)
}
