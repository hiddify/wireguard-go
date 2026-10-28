package hiddify

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The special packets of working WARP AmneziaWG configs: a DNS query for google.com with a
// random transaction id, and a SIP INVITE.
const (
	hDNSGoogleA = "<r 2><b 0x0100000100000000000106676f6f676c6503636f6d00000100010000291000000000000000>"
	hSIPStart   = "<b 0x494e56495445207369703a>" // "INVITE sip:"
)

func TestH_ExpandPacket(t *testing.T) {
	packet, err := ExpandPacket(hDNSGoogleA)
	require.NoError(t, err)
	query, _ := hex.DecodeString("0100000100000000000106676f6f676c6503636f6d00000100010000291000000000000000")
	require.Len(t, packet, 2+len(query))
	require.Equal(t, query, packet[2:], "random transaction id, then the query")

	packet, err = ExpandPacket(hSIPStart + "<rc 8><rd 3><t>")
	require.NoError(t, err)
	require.True(t, bytes.HasPrefix(packet, []byte("INVITE sip:")))
	require.Len(t, packet, len("INVITE sip:")+8+3+4)
	for _, c := range packet[len("INVITE sip:")+8 : len("INVITE sip:")+11] {
		require.True(t, c >= '0' && c <= '9')
	}

	packet, err = ExpandPacket("<qi www.example.com>")
	require.NoError(t, err)
	require.Equal(t, byte(0xc0), packet[0]&0xf0, "a QUIC long header Initial")

	for _, bad := range []string{"", "<x 1>", "<b zz>", "<r -1>", "<r 1", "junk<r 1>", "<r 1>junk"} {
		_, err := ExpandPacket(bad)
		require.Error(t, err, bad)
	}
}

func TestH_FakePacketsBuild(t *testing.T) {
	options := FakePacketOptions{
		Enabled: true,
		Packets: []string{hDNSGoogleA, hSIPStart},
		Mode:    NoiseModeRaw,
		Count:   Range{3, 3},
		Size:    Range{56, 160},
		Delay:   Range{0, 0},
	}
	packets, err := options.Build()
	require.NoError(t, err)
	require.Len(t, packets, 5, "the templates, then the junk packets")
	require.Equal(t, []byte("INVITE sip:"), packets[1].Data)
	for _, packet := range packets {
		require.True(t, packet.NoModify, "sent as they are")
	}
	for _, packet := range packets[2:] {
		require.GreaterOrEqual(t, len(packet.Data), 56)
		require.LessOrEqual(t, len(packet.Data), 160)
	}

	options = FakePacketOptions{Enabled: true, Count: Range{2, 2}, Size: Range{5, 10}, Delay: Range{2, 2}, Header: []byte{0xc0}}
	packets, err = options.Build()
	require.NoError(t, err)
	require.Len(t, packets, 2)
	require.Equal(t, byte(0xc0), packets[0].Data[0], "the default packet starts from header")
	require.Equal(t, 2*time.Millisecond, packets[0].Delay)
	require.Zero(t, packets[1].Delay, "no wait after the last one")

	packets, err = FakePacketOptions{Count: Range{2, 2}, Size: Range{5, 5}}.Build()
	require.NoError(t, err)
	require.Empty(t, packets, "disabled")
	require.Error(t, FakePacketOptions{Packets: []string{"<x>"}}.Validate())
}
