package hiddify

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"testing"
	"time"
)

func hHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

// RFC 9001 Appendix A.1: the client Initial keys of connection ID 8394c8f03e515708.
func TestH_QUICInitialKeys(t *testing.T) {
	keys := quicClientInitialKeys(hHex(t, "8394c8f03e515708"))
	for name, pair := range map[string][2][]byte{
		"key": {keys.key, hHex(t, "1f369613dd76d5467730efcbe3b1a22d")},
		"iv":  {keys.iv, hHex(t, "fa044b2f42a3fd3b46fb255c")},
		"hp":  {keys.hp, hHex(t, "9f50449e04a0e810283a1e9933adedd2")},
	} {
		if !bytes.Equal(pair[0], pair[1]) {
			t.Fatalf("%s = %x, want %x", name, pair[0], pair[1])
		}
	}
}

// RFC 9001 Appendix A.2: the header protection mask of the client Initial, and the protected
// header it gives.
func TestH_QUICHeaderProtection(t *testing.T) {
	keys := quicClientInitialKeys(hHex(t, "8394c8f03e515708"))
	mask, err := quicHeaderMask(keys.hp, hHex(t, "d1b1c98dd7689fb8ec11d242b123dc9b"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mask[:5], hHex(t, "437b9aec36")) {
		t.Fatalf("mask = %x", mask[:5])
	}
	header := hHex(t, "c300000001088394c8f03e5157080000449e00000002")
	header[0] ^= mask[0] & 0x0f
	for i := range 4 {
		header[len(header)-4+i] ^= mask[1+i]
	}
	if !bytes.Equal(header, hHex(t, "c000000001088394c8f03e5157080000449e7b9aec34")) {
		t.Fatalf("protected header = %x", header)
	}
}

// hOpenInitial removes the protection of a client Initial (RFC 9001 5.4, 5.3) and returns its
// destination connection ID, packet number and frames.
func hOpenInitial(t *testing.T, packet []byte) ([]byte, uint32, []byte) {
	t.Helper()
	packet = append([]byte(nil), packet...)
	if packet[0]&0xf0 != 0xc0 || binary.BigEndian.Uint32(packet[1:5]) != 1 {
		t.Fatalf("not a QUIC v1 Initial: %x", packet[:5])
	}
	offset := 5
	destinationID := packet[offset+1 : offset+1+int(packet[offset])]
	offset += 1 + len(destinationID)
	offset += 1 + int(packet[offset]) // source connection ID
	offset++                          // token length 0
	length := int(binary.BigEndian.Uint16(packet[offset:]) & 0x3fff)
	offset += 2
	keys := quicClientInitialKeys(destinationID)
	mask, err := quicHeaderMask(keys.hp, packet[offset+4:offset+20])
	if err != nil {
		t.Fatal(err)
	}
	packet[0] ^= mask[0] & 0x0f
	packetNumberLength := int(packet[0]&0x03) + 1
	for i := range packetNumberLength {
		packet[offset+i] ^= mask[1+i]
	}
	var packetNumber uint32
	for i := range packetNumberLength {
		packetNumber = packetNumber<<8 | uint32(packet[offset+i])
	}
	header := packet[:offset+packetNumberLength]
	nonce := append([]byte(nil), keys.iv...)
	for i := range packetNumberLength {
		nonce[len(nonce)-packetNumberLength+i] ^= header[offset+i]
	}
	block, _ := aes.NewCipher(keys.key)
	aead, _ := cipher.NewGCM(block)
	frames, err := aead.Open(nil, nonce, packet[offset+packetNumberLength:offset+length], header)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if offset+length != len(packet) {
		t.Fatalf("length field %d does not match the packet", length)
	}
	return destinationID, packetNumber, frames
}

// hParseClientHello hands a ClientHello to Go's TLS server and returns what it read.
func hParseClientHello(t *testing.T, hello []byte) *tls.ClientHelloInfo {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	result := make(chan *tls.ClientHelloInfo, 1)
	go func() {
		record := []byte{22, 3, 1, byte(len(hello) >> 8), byte(len(hello))}
		client.Write(append(record, hello...))
	}()
	tlsServer := tls.Server(server, &tls.Config{GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
		result <- info
		return nil, errors.New("done")
	}})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	tlsServer.HandshakeContext(ctx)
	server.Close()
	select {
	case info := <-result:
		return info
	default:
		t.Fatal("the ClientHello was not parsed")
		return nil
	}
}

// The packets decrypt like real Initials, are at least 1200 bytes, share one connection with
// increasing packet numbers, and the first carries a valid ClientHello for the SNI with ALPN h3.
func TestH_QUICInitialPackets(t *testing.T) {
	packets, err := QUICInitialPackets("www.example.com", 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(packets) != 3 {
		t.Fatalf("%d packets", len(packets))
	}
	var connectionID []byte
	for i, packet := range packets {
		if len(packet) < quicMinInitialSize {
			t.Fatalf("packet %d is %d bytes", i, len(packet))
		}
		destinationID, packetNumber, frames := hOpenInitial(t, packet)
		if i == 0 {
			connectionID = destinationID
		} else if !bytes.Equal(connectionID, destinationID) {
			t.Fatal("the packets belong to different connections")
		}
		if packetNumber != uint32(i) {
			t.Fatalf("packet %d has number %d", i, packetNumber)
		}
		if i > 0 {
			if frames[0] != 0x01 {
				t.Fatalf("packet %d does not start with PING", i)
			}
			continue
		}
		if frames[0] != 0x06 || frames[1] != 0x00 {
			t.Fatalf("no CRYPTO frame at offset 0: %x", frames[:2])
		}
		length := int(binary.BigEndian.Uint16(frames[2:4]) & 0x3fff)
		info := hParseClientHello(t, frames[4:4+length])
		if info.ServerName != "www.example.com" {
			t.Fatalf("SNI = %q", info.ServerName)
		}
		if len(info.SupportedProtos) != 1 || info.SupportedProtos[0] != "h3" {
			t.Fatalf("ALPN = %v", info.SupportedProtos)
		}
		if len(info.SupportedVersions) != 1 || info.SupportedVersions[0] != tls.VersionTLS13 {
			t.Fatalf("versions = %v", info.SupportedVersions)
		}
	}
	other, _ := QUICInitialPackets("www.example.com", 1)
	otherID, _, _ := hOpenInitial(t, other[0])
	if bytes.Equal(otherID, connectionID) {
		t.Fatal("each call starts a new connection")
	}
}
