package hiddify

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// NoiseModeRaw makes the fake packets plain random bytes of Size, with no header, as Xray's
// random noise and AmneziaWG's junk packets.
const NoiseModeRaw = "raw"

// FakePacket is one packet to send before a handshake initiation.
type FakePacket struct {
	Data []byte
	// NoModify sends it as is, without the bind's changes (the reserved bytes of WARP).
	NoModify bool
	// Delay is the wait before the next packet.
	Delay time.Duration
}

// Build returns the fake packets to send before a handshake initiation: the Packets templates in
// order, then Count packets of the mode. The device and the WARP scanner's probe both send these,
// so a probe looks like the device's handshake.
func (o FakePacketOptions) Build() ([]FakePacket, error) {
	if !o.Enabled {
		return nil, nil
	}
	var packets []FakePacket
	for _, template := range o.Packets {
		data, err := ExpandPacket(template)
		if err != nil {
			return nil, err
		}
		packets = append(packets, FakePacket{Data: data, NoModify: true, Delay: o.delay()})
	}
	if o.Count.To == 0 || o.Size.To == 0 && o.Mode != NoiseModeQUIC {
		return packets, nil
	}
	count := o.Count.Rand()
	var quicPackets [][]byte
	if o.Mode == NoiseModeQUIC { // the start of a QUIC connection to the configured SNI
		var err error
		quicPackets, err = QUICInitialPackets(o.QUICServerName(), count)
		if err != nil {
			return nil, err
		}
	}
	for i := range count {
		packet := FakePacket{Delay: o.delay()}
		switch o.Mode {
		case NoiseModeQUIC:
			// as is: the bind's reserved bytes would overwrite the QUIC version
			packet.Data, packet.NoModify = quicPackets[i], true
		case NoiseModeRaw:
			packet.Data, packet.NoModify = randomBytes(o.Size.Rand()), true
		default:
			packet.Data, packet.NoModify = knockerPacket(o.Header, randomBytes(o.Size.Rand())), o.NoModify
		}
		packets = append(packets, packet)
	}
	if len(packets) > 0 {
		packets[len(packets)-1].Delay = 0
	}
	return packets, nil
}

// Validate reports a template that cannot be expanded, when the config is read.
func (o FakePacketOptions) Validate() error {
	for i, template := range o.Packets {
		if _, err := ExpandPacket(template); err != nil {
			return fmt.Errorf("noise packet %d: %w", i+1, err)
		}
	}
	return nil
}

func (o FakePacketOptions) delay() time.Duration {
	return time.Duration(o.Delay.Rand()) * time.Millisecond
}

// knockerPacket is the default fake packet (from GFW-knocker): a short long-header-like start,
// its first byte picked from header when set, then payload.
func knockerPacket(header []byte, payload []byte) []byte {
	var start []byte
	if len(header) > 0 {
		start = []byte{header[RandBetween(0, int64(len(header)-1))], 0x00, 0x00, 0x00, 0x01, 0x08}
	} else {
		start = []byte{0x00, 0x00, 0x00, 0x01, 0x08}
	}
	packet := make([]byte, 0, len(start)+8+4+len(payload))
	packet = append(packet, start...)
	packet = append(packet, randomBytes(8)...)
	packet = append(packet, 0x00, 0x00, 0x44, 0xD0)
	return append(packet, payload...)
}

func randomBytes(n int) []byte {
	data := make([]byte, n)
	rand.Read(data)
	return data
}

const (
	alphanumeric = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	digits       = "0123456789"
)

// ExpandPacket builds a packet from a template in the AmneziaWG I1–I5 syntax, so the special
// packets of AmneziaWG configs work in plain WireGuard noise too:
//
//	<b 0xHEX>  these bytes
//	<r N>      N random bytes
//	<rc N>     N random letters and digits
//	<rd N>     N random digits
//	<t>        the Unix time, 4 bytes big-endian
//	<qi SNI>   a QUIC Initial with a ClientHello for SNI (www.google.com when empty)
func ExpandPacket(template string) ([]byte, error) {
	var packet []byte
	remaining := template
	for {
		start := strings.IndexByte(remaining, '<')
		if start == -1 {
			if strings.TrimSpace(remaining) != "" {
				return nil, fmt.Errorf("text outside a tag: %q", strings.TrimSpace(remaining))
			}
			break
		}
		if strings.TrimSpace(remaining[:start]) != "" {
			return nil, fmt.Errorf("text outside a tag: %q", strings.TrimSpace(remaining[:start]))
		}
		end := strings.IndexByte(remaining[start:], '>')
		if end == -1 {
			return nil, fmt.Errorf("missing > in %q", remaining[start:])
		}
		fields := strings.Fields(remaining[start+1 : start+end])
		remaining = remaining[start+end+1:]
		if len(fields) == 0 {
			return nil, fmt.Errorf("empty tag")
		}
		var value string
		if len(fields) > 1 {
			value = fields[1]
		}
		size := func() (int, error) {
			n, err := strconv.Atoi(value)
			if err != nil || n < 0 || n > 65535 {
				return 0, fmt.Errorf("<%s> needs a length from 0 to 65535, not %q", fields[0], value)
			}
			return n, nil
		}
		switch fields[0] {
		case "b":
			data, err := hex.DecodeString(strings.TrimPrefix(strings.TrimPrefix(value, "0x"), "0X"))
			if err != nil {
				return nil, fmt.Errorf("<b> needs hex bytes: %w", err)
			}
			packet = append(packet, data...)
		case "r":
			n, err := size()
			if err != nil {
				return nil, err
			}
			packet = append(packet, randomBytes(n)...)
		case "rc", "rd":
			n, err := size()
			if err != nil {
				return nil, err
			}
			charset := alphanumeric
			if fields[0] == "rd" {
				charset = digits
			}
			for _, b := range randomBytes(n) {
				packet = append(packet, charset[int(b)%len(charset)])
			}
		case "t":
			packet = binary.BigEndian.AppendUint32(packet, uint32(time.Now().Unix()))
		case "qi":
			sni := value
			if sni == "" {
				sni = DefaultQUICServerName
			}
			initials, err := QUICInitialPackets(sni, 1)
			if err != nil {
				return nil, err
			}
			packet = append(packet, initials[0]...)
		default:
			return nil, fmt.Errorf("unknown tag <%s>", fields[0])
		}
	}
	if len(packet) == 0 {
		return nil, fmt.Errorf("empty packet")
	}
	return packet, nil
}
