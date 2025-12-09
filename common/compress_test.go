package common

import "testing"

func TestCompressDecompressRoundtrip(t *testing.T) {
	data := []byte("hello world, compress me")
	comp, err := CompressPayload(data)
	if err != nil {
		t.Fatalf("compress: %v", err)
	}
	dec, err := DecompressPayload(comp, 1024)
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}
	if string(dec) != string(data) {
		t.Fatalf("roundtrip mismatch: %q vs %q", dec, data)
	}
}

func TestDecompressTooLarge(t *testing.T) {
	data := []byte("aaaaaa")
	comp, err := CompressPayload(data)
	if err != nil {
		t.Fatalf("compress: %v", err)
	}
	if _, err := DecompressPayload(comp, 2); err == nil {
		t.Fatalf("expected size limit error")
	}
}
