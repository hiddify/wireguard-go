package hiddify

import (
	"bytes"
	"testing"
)

// A preset named as the mode sends its packets, then its junk; its short names and any case work.
func TestH_NoiseModeNamesAPreset(t *testing.T) {
	for _, mode := range []string{"sip", "SIP", "dns", "dns-google", "random", "stun", "quic-mimic"} {
		packets, err := FakePacketOptions{Enabled: true, Mode: mode}.Build()
		if err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
		preset, _ := NoisePresetByName(mode)
		if want := len(preset.Noise.Packets) + int(preset.Noise.Count.To); len(packets) != want {
			t.Fatalf("%s: %d packets, want %d", mode, len(packets), want)
		}
		for _, packet := range packets {
			if !packet.NoModify {
				t.Fatalf("%s: a preset packet would get the reserved bytes", mode)
			}
		}
	}
	packets, _ := FakePacketOptions{Enabled: true, Mode: "sip"}.Build()
	if !bytes.HasPrefix(packets[0].Data, []byte("INVITE sip:")) || !bytes.HasPrefix(packets[1].Data, []byte("SIP/2.0 100 Trying")) {
		t.Fatalf("sip does not start with an INVITE and its answer: %q", packets[0].Data[:16])
	}
	packets, _ = FakePacketOptions{Enabled: true, Mode: "stun"}.Build()
	if !bytes.Equal(packets[0].Data[:8], []byte{0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42}) || len(packets[0].Data) != 20 {
		t.Fatalf("stun does not start with a Binding Request: %x", packets[0].Data)
	}
}

// Count, size and delay set next to a preset win, and extra packets follow the preset's.
func TestH_NoisePresetKeepsExplicitValues(t *testing.T) {
	noise := FakePacketOptions{
		Enabled: true, Mode: "sip", Count: Range{From: 2, To: 2}, Size: Range{From: 30, To: 30},
		Packets: []string{"<b 0xabcd>"},
	}.WithPreset()
	if noise.Count.To != 2 || noise.Size.From != 30 || len(noise.Packets) != 3 || noise.Packets[2] != "<b 0xabcd>" {
		t.Fatalf("explicit values lost: %+v", noise)
	}
}

// quic without a count sends the quic preset's Initials; with one, that many.
func TestH_NoiseModeQUICGetsACount(t *testing.T) {
	if packets, err := (FakePacketOptions{Enabled: true, Mode: NoiseModeQUIC}).Build(); err != nil || len(packets) < 2 {
		t.Fatalf("quic without a count: %d packets, %v", len(packets), err)
	}
	if packets, _ := (FakePacketOptions{Enabled: true, Mode: NoiseModeQUIC, Count: Range{From: 1, To: 1}}).Build(); len(packets) != 1 {
		t.Fatalf("quic with count 1: %d packets", len(packets))
	}
}

// The raw mode keeps its meaning, and an unknown name stays the knocker's.
func TestH_NoiseModesThatAreNotPresets(t *testing.T) {
	for _, mode := range []string{NoiseModeRaw, "m4", ""} {
		noise := FakePacketOptions{Enabled: true, Mode: mode}
		if got := noise.WithPreset(); got.Mode != mode || len(got.Packets) != 0 {
			t.Fatalf("%q changed to %+v", mode, got)
		}
	}
}
