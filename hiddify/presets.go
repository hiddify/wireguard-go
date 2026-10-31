package hiddify

import "strings"

// NoisePreset is named noise that gets a WireGuard handshake through on some networks, taken
// from WARP configs that work: Xray's random noise, and the special packets of AmneziaWG configs
// that make the start of the flow look like DNS, QUIC, SIP or STUN. A preset is chosen by name:
// the mode of WireGuard noise, the ip of an AmneziaWG endpoint, and the WARP scanner, which tries
// them in this order when no endpoint answers with the configured noise.
type NoisePreset struct {
	Name  string
	Noise FakePacketOptions
}

var NoisePresets = []NoisePreset{
	// Xray WARP: wnoise=random, wnoisecount=5, wpayloadsize=5-10, wnoisedelay=2-5
	{"xray-random", FakePacketOptions{
		Mode: NoiseModeRaw, Count: Range{From: 5, To: 5}, Size: Range{From: 5, To: 10}, Delay: Range{From: 2, To: 5},
	}},
	// the start of a QUIC connection to www.google.com
	{"quic", FakePacketOptions{
		Mode: NoiseModeQUIC, Count: Range{From: 2, To: 4}, Delay: Range{From: 10, To: 30},
	}},
	// DNS queries for google.com (A, AAAA, HTTPS) with a random id, then junk
	{"dns-google", FakePacketOptions{
		Packets: []string{
			"<r 2><b 0x0100000100000000000106676f6f676c6503636f6d00000100010000291000000000000000>",
			"<r 2><b 0x0100000100000000000106676f6f676c6503636f6d00001c00010000291000000000000000>",
			"<r 2><b 0x0100000100000000000106676f6f676c6503636f6d000041000100002904d0000000000000>",
		},
		Mode: NoiseModeRaw, Count: Range{From: 6, To: 6}, Size: Range{From: 56, To: 160},
	}},
	// DNS queries for cloudflare.com (A, AAAA), then junk
	{"dns-cloudflare", FakePacketOptions{
		Packets: []string{
			"<r 2><b 0x010000010000000000010a636c6f7564666c61726503636f6d000001000100002904d0000000000000>",
			"<r 2><b 0x010000010000000000010a636c6f7564666c61726503636f6d00001c000100002904d0000000000000>",
		},
		Mode: NoiseModeRaw, Count: Range{From: 9, To: 9}, Size: Range{From: 81, To: 224},
	}},
	// DNS queries for www.cloudflare.com (A, AAAA), then junk
	{"dns-www-cloudflare", FakePacketOptions{
		Packets: []string{
			"<r 2><b 0x01000001000000000001037777770a636c6f7564666c61726503636f6d000001000100002904d0000000000000>",
			"<r 2><b 0x01000001000000000001037777770a636c6f7564666c61726503636f6d00001c00010000291000000000000000>",
		},
		Mode: NoiseModeRaw, Count: Range{From: 6, To: 6}, Size: Range{From: 43, To: 109},
	}},
	// a QUIC Initial and a short-header packet, then junk
	{"quic-mimic", FakePacketOptions{
		Packets: []string{
			"<b 0xc30000000108f9a15db6b62f2eca00004102a86db502291b19dedd8bae27fc40532582410069940fe6d06c77e2312ea305087f47592f26b626d87812ce68e2ae6fdeac49f3137eb88bbaa540b7de515deb24733a58af75f03acc9dd676ac9a7ee96ea837006e8ed1a0d110adc21be31caf11d83a4ec7fbe330b944ee4b278783551a1090c8d38f142e9ee102442cd8e1210a5fcf727222887cf1d7b47c536083ed4644569bdeefa8388efbc80a7a86a7b526273f43d3063df805db3a5aa8d4a35e9a097f32bd1eb4770ce59a589694016d0d14baeb2c415b50b04d06f06e0ea0626678accbfda916a61d3f623cfd5286d8723a8c946ab1ab2541ef0a1c959e96bc9accbb5a598bc2722ffdc391c5c35ef91c06fb><r 934>",
			"<b 0x47e4a9a16a11ea385d><r 29>",
		},
		Mode: NoiseModeRaw, Count: Range{From: 4, To: 4}, Size: Range{From: 60, To: 199},
	}},
	// a SIP INVITE and its "100 Trying" answer, then junk
	{"sip", FakePacketOptions{
		Packets: []string{
			"<b 0x494e56495445207369703a6672616e6b407369702e6578616d706c652e6f7267205349502f322e300d0a5669613a205349502f322e302f55445020706331372e736f667470686f6e652e6578616d706c652e6e65743b6272616e63683d7a39684734624b446b366f536e54327839377a384279620d0a4d61782d466f7277617264733a2036390d0a546f3a204672616e6b203c7369703a6672616e6b407369702e6578616d706c652e6f72673e0d0a46726f6d3a204572696e203c7369703a6572696e40736f667470686f6e652e6578616d706c652e6e65743e3b7461673d35353531323230380d0a43616c6c2d49443a203238643533656365616438613430306240706331372e736f667470686f6e652e6578616d706c652e6e65740d0a435365713a2036363038333720494e564954450d0a436f6e746163743a203c7369703a6572696e40706331372e736f667470686f6e652e6578616d706c652e6e65743e0d0a436f6e74656e742d547970653a206170706c69636174696f6e2f7364700d0a436f6e74656e742d4c656e6774683a20300d0a0d0a>",
			"<b 0x5349502f322e302031303020547279696e670d0a5669613a205349502f322e302f55445020706331372e736f667470686f6e652e6578616d706c652e6e65743b6272616e63683d7a39684734624b446b366f536e54327839377a384279620d0a546f3a204672616e6b203c7369703a6672616e6b407369702e6578616d706c652e6f72673e0d0a46726f6d3a204572696e203c7369703a6572696e40736f667470686f6e652e6578616d706c652e6e65743e3b7461673d35353531323230380d0a43616c6c2d49443a203238643533656365616438613430306240706331372e736f667470686f6e652e6578616d706c652e6e65740d0a435365713a2036363038333720494e564954450d0a436f6e74656e742d4c656e6774683a20300d0a0d0a>",
		},
		Mode: NoiseModeRaw, Count: Range{From: 10, To: 10}, Size: Range{From: 42, To: 224},
	}},
	// STUN Binding Requests, as a video call or WebRTC client checks its address, then junk
	{"stun", FakePacketOptions{
		Packets: []string{
			"<b 0x000100002112a442><r 12>",
			"<b 0x000100082112a442><r 12><b 0x0024000400000000>",
		},
		Mode: NoiseModeRaw, Count: Range{From: 4, To: 4}, Size: Range{From: 40, To: 120},
	}},
}

// noisePresetAliases are the short names of presets.
var noisePresetAliases = map[string]string{"dns": "dns-google", "random": "xray-random"}

// NoisePresetByName returns the preset called name, or by one of its short names (dns, random),
// in any case.
func NoisePresetByName(name string) (NoisePreset, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	if alias, ok := noisePresetAliases[name]; ok {
		name = alias
	}
	for _, preset := range NoisePresets {
		if preset.Name == name {
			return preset, true
		}
	}
	return NoisePreset{}, false
}

// WithPreset expands a Mode that names a preset (see NoisePresets) into the preset's packets and
// junk. Count, Size, Delay and SNI set next to it win over the preset's, and its Packets are sent
// after the preset's. The quic mode is the quic preset, so it gets a count when it has none; the
// raw mode is left as it is.
func (o FakePacketOptions) WithPreset() FakePacketOptions {
	if o.Mode == NoiseModeRaw {
		return o
	}
	preset, ok := NoisePresetByName(o.Mode)
	if !ok {
		return o
	}
	noise := preset.Noise
	noise.Enabled = o.Enabled
	if o.Count.To != 0 {
		noise.Count = o.Count
	}
	if o.Size.To != 0 {
		noise.Size = o.Size
	}
	if o.Delay.To != 0 {
		noise.Delay = o.Delay
	}
	if o.SNI != "" {
		noise.SNI = o.SNI
	}
	noise.Packets = append(append([]string(nil), noise.Packets...), o.Packets...)
	noise.NoModify = o.NoModify
	return noise
}
