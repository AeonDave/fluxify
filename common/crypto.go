package common

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

const (
	SessionKeySize = 32
	nonceSize      = 12
)

// GenerateSessionKey returns a random 32-byte key suitable for AES-256-GCM.
func GenerateSessionKey() ([]byte, error) {
	key := make([]byte, SessionKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

// EncryptPacket seals plaintext with AES-GCM using the given session key.
// The returned packet is header || nonce || ciphertext. Header.Length is set to len(nonce)+len(ciphertext).
// The header bytes are used as AAD to protect metadata integrity.
func EncryptPacket(key []byte, h PacketHeader, plaintext []byte) ([]byte, error) {
	return EncryptPacketInto(nil, key, h, plaintext)
}

// EncryptPacketInto seals plaintext into dst (if capacity allows, otherwise allocates).
func EncryptPacketInto(dst []byte, key []byte, h PacketHeader, plaintext []byte) ([]byte, error) {
	if len(key) != SessionKeySize {
		return nil, fmt.Errorf("invalid key length %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	// Length must reflect nonce+ciphertext so that AAD matches on decrypt.
	payloadLen := nonceSize + len(plaintext) + gcm.Overhead()
	h.Length = uint16(payloadLen)
	hdrBytes, err := h.Marshal()
	if err != nil {
		return nil, err
	}

	// Output format: Header || Nonce || Ciphertext
	needed := len(hdrBytes) + len(nonce) + len(plaintext) + gcm.Overhead()
	var pkt []byte
	if cap(dst) >= needed {
		pkt = dst[:0]
	} else {
		pkt = make([]byte, 0, needed)
	}

	pkt = append(pkt, hdrBytes...)
	pkt = append(pkt, nonce...)
	// Seal appends ciphertext to the provided buffer
	pkt = gcm.Seal(pkt, nonce, plaintext, hdrBytes)
	return pkt, nil
}

// DecryptPacket authenticates and decrypts a packet produced by EncryptPacket.
// Returns the header and plaintext payload.
func DecryptPacket(key []byte, packet []byte) (PacketHeader, []byte, error) {
	return DecryptPacketInto(nil, key, packet)
}

// DecryptPacketInto authenticates and decrypts into dst.
func DecryptPacketInto(dst []byte, key []byte, packet []byte) (PacketHeader, []byte, error) {
	var h PacketHeader
	if len(key) != SessionKeySize {
		return h, nil, fmt.Errorf("invalid key length %d", len(key))
	}
	if len(packet) < HeaderSize+nonceSize+gcmMinOverhead {
		return h, nil, fmt.Errorf("packet too small: %d", len(packet))
	}
	if err := h.Unmarshal(packet[:HeaderSize]); err != nil {
		return h, nil, err
	}
	payload := packet[HeaderSize:]
	if len(payload) != int(h.Length) {
		return h, nil, fmt.Errorf("length mismatch header %d payload %d", h.Length, len(payload))
	}
	if len(payload) < nonceSize+gcmMinOverhead {
		return h, nil, fmt.Errorf("payload too small")
	}
	nonce := payload[:nonceSize]
	ciphertext := payload[nonceSize:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return h, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return h, nil, err
	}

	plaintext, err := gcm.Open(dst[:0], nonce, ciphertext, packet[:HeaderSize])
	if err != nil {
		return h, nil, err
	}
	return h, plaintext, nil
}

const gcmMinOverhead = 16 // GCM tag size

// EncodeKeyBase64 encodes a binary session key for transport.
func EncodeKeyBase64(key []byte) string {
	return base64.StdEncoding.EncodeToString(key)
}

// DecodeKeyBase64 decodes a base64 key string.
func DecodeKeyBase64(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != SessionKeySize {
		return nil, fmt.Errorf("invalid key size %d", len(b))
	}
	return b, nil
}
