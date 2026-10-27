package hiddify

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// QUIC version 1 Initial packets (RFC 9000, RFC 9001), used as noise that looks like the start of
// a QUIC connection to sni: DPI that decrypts Initials (their keys come from the destination
// connection ID) finds a well-formed TLS 1.3 ClientHello with ALPN h3.

const (
	quicMinInitialSize  = 1200
	quicPacketNumberLen = 4
)

var quicV1InitialSalt = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}

// QUICInitialPackets returns count client Initial packets of one connection to sni: the first
// carries the ClientHello, the others PING frames, as retransmissions would.
func QUICInitialPackets(sni string, count int) ([][]byte, error) {
	if count <= 0 {
		return nil, nil
	}
	destinationID := make([]byte, 8)
	sourceID := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, destinationID); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(rand.Reader, sourceID); err != nil {
		return nil, err
	}
	hello, err := quicClientHello(sni, sourceID)
	if err != nil {
		return nil, err
	}
	packets := make([][]byte, 0, count)
	for packetNumber := range count {
		var frames []byte
		if packetNumber == 0 {
			frames = quicCryptoFrame(hello)
		} else {
			frames = []byte{0x01} // PING
		}
		packet, err := quicInitialPacket(destinationID, sourceID, uint32(packetNumber), frames)
		if err != nil {
			return nil, err
		}
		packets = append(packets, packet)
	}
	return packets, nil
}

type quicKeys struct {
	key, iv, hp []byte
}

func quicClientInitialKeys(destinationID []byte) quicKeys {
	initialSecret := hkdf.Extract(sha256.New, destinationID, quicV1InitialSalt)
	clientSecret := hkdfExpandLabel(initialSecret, "client in", 32)
	return quicKeys{
		key: hkdfExpandLabel(clientSecret, "quic key", 16),
		iv:  hkdfExpandLabel(clientSecret, "quic iv", 12),
		hp:  hkdfExpandLabel(clientSecret, "quic hp", 16),
	}
}

// hkdfExpandLabel is TLS 1.3's HKDF-Expand-Label with an empty context.
func hkdfExpandLabel(secret []byte, label string, length int) []byte {
	fullLabel := "tls13 " + label
	info := make([]byte, 0, 4+len(fullLabel))
	info = binary.BigEndian.AppendUint16(info, uint16(length))
	info = append(info, byte(len(fullLabel)))
	info = append(info, fullLabel...)
	info = append(info, 0)
	out := make([]byte, length)
	io.ReadFull(hkdf.Expand(sha256.New, secret, info), out)
	return out
}

// quicInitialPacket builds and protects a client Initial with frames, padded to the minimum size.
func quicInitialPacket(destinationID, sourceID []byte, packetNumber uint32, frames []byte) ([]byte, error) {
	header := []byte{0xc0 | (quicPacketNumberLen - 1), 0, 0, 0, 1}
	header = append(header, byte(len(destinationID)))
	header = append(header, destinationID...)
	header = append(header, byte(len(sourceID)))
	header = append(header, sourceID...)
	header = append(header, 0) // token length
	// pad the payload so that the whole packet reaches the minimum Initial size
	fixed := len(header) + 2 + quicPacketNumberLen + 16
	if padding := quicMinInitialSize - fixed - len(frames); padding > 0 {
		frames = append(frames, make([]byte, padding)...)
	}
	length := quicPacketNumberLen + len(frames) + 16
	if length >= 1<<14 {
		return nil, errors.New("QUIC Initial too large")
	}
	header = binary.BigEndian.AppendUint16(header, 0x4000|uint16(length))
	packetNumberOffset := len(header)
	header = binary.BigEndian.AppendUint32(header, packetNumber)
	return protectQUICInitial(quicClientInitialKeys(destinationID), header, packetNumberOffset, frames)
}

// protectQUICInitial encrypts the payload (AEAD_AES_128_GCM) and applies header protection.
func protectQUICInitial(keys quicKeys, header []byte, packetNumberOffset int, payload []byte) ([]byte, error) {
	block, err := aes.NewCipher(keys.key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := append([]byte(nil), keys.iv...)
	packetNumber := header[packetNumberOffset : packetNumberOffset+quicPacketNumberLen]
	for i := range packetNumber {
		nonce[len(nonce)-quicPacketNumberLen+i] ^= packetNumber[i]
	}
	packet := aead.Seal(append([]byte(nil), header...), nonce, payload, header)
	mask, err := quicHeaderMask(keys.hp, packet[packetNumberOffset+4:packetNumberOffset+4+16])
	if err != nil {
		return nil, err
	}
	packet[0] ^= mask[0] & 0x0f
	for i := range quicPacketNumberLen {
		packet[packetNumberOffset+i] ^= mask[1+i]
	}
	return packet, nil
}

func quicHeaderMask(hp []byte, sample []byte) ([]byte, error) {
	block, err := aes.NewCipher(hp)
	if err != nil {
		return nil, err
	}
	mask := make([]byte, 16)
	block.Encrypt(mask, sample)
	return mask, nil
}

func quicVarint(value uint64) []byte {
	switch {
	case value < 1<<6:
		return []byte{byte(value)}
	case value < 1<<14:
		return binary.BigEndian.AppendUint16(nil, 0x4000|uint16(value))
	case value < 1<<30:
		return binary.BigEndian.AppendUint32(nil, 0x80000000|uint32(value))
	}
	return binary.BigEndian.AppendUint64(nil, 0xc000000000000000|value)
}

func quicCryptoFrame(data []byte) []byte {
	frame := []byte{0x06, 0x00} // CRYPTO, offset 0
	frame = append(frame, quicVarint(uint64(len(data)))...)
	return append(frame, data...)
}

// quicClientHello builds a TLS 1.3 ClientHello as QUIC clients send it.
func quicClientHello(sni string, sourceID []byte) ([]byte, error) {
	random := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, random); err != nil {
		return nil, err
	}
	private := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, private); err != nil {
		return nil, err
	}
	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	var extensions []byte
	extension := func(kind uint16, data []byte) {
		extensions = binary.BigEndian.AppendUint16(extensions, kind)
		extensions = binary.BigEndian.AppendUint16(extensions, uint16(len(data)))
		extensions = append(extensions, data...)
	}
	if sni != "" {
		name := []byte{0}
		name = binary.BigEndian.AppendUint16(name, uint16(len(sni)))
		name = append(name, sni...)
		extension(0, append(binary.BigEndian.AppendUint16(nil, uint16(len(name))), name...))
	}
	extension(10, []byte{0, 4, 0x00, 0x1d, 0x00, 0x17})                                                  // supported_groups: x25519, secp256r1
	extension(13, []byte{0, 12, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01}) // signature_algorithms
	extension(16, []byte{0, 3, 2, 'h', '3'})                                                             // ALPN h3
	extension(43, []byte{2, 0x03, 0x04})                                                                 // supported_versions: TLS 1.3
	extension(45, []byte{1, 1})                                                                          // psk_key_exchange_modes: psk_dhe_ke
	keyShare := binary.BigEndian.AppendUint16(nil, 2+2+32)
	keyShare = append(keyShare, 0x00, 0x1d, 0, 32)
	extension(51, append(keyShare, public...))
	var parameters []byte
	parameter := func(id uint64, value []byte) {
		parameters = append(parameters, quicVarint(id)...)
		parameters = append(parameters, quicVarint(uint64(len(value)))...)
		parameters = append(parameters, value...)
	}
	parameter(0x01, quicVarint(30000))    // max_idle_timeout
	parameter(0x03, quicVarint(1472))     // max_udp_payload_size
	parameter(0x04, quicVarint(15728640)) // initial_max_data
	parameter(0x05, quicVarint(6291456))  // initial_max_stream_data_bidi_local
	parameter(0x06, quicVarint(6291456))  // initial_max_stream_data_bidi_remote
	parameter(0x07, quicVarint(6291456))  // initial_max_stream_data_uni
	parameter(0x08, quicVarint(100))      // initial_max_streams_bidi
	parameter(0x09, quicVarint(103))      // initial_max_streams_uni
	parameter(0x0f, sourceID)             // initial_source_connection_id
	extension(0x39, parameters)           // quic_transport_parameters

	body := []byte{0x03, 0x03}
	body = append(body, random...)
	body = append(body, 0)                                        // legacy_session_id
	body = append(body, 0, 6, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03) // cipher suites
	body = append(body, 1, 0)                                     // compression: null
	body = binary.BigEndian.AppendUint16(body, uint16(len(extensions)))
	body = append(body, extensions...)
	hello := []byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(hello, body...), nil
}
