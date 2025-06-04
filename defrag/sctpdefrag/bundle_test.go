package sctpdefrag_test

import (
	"encoding/hex"
	"github.com/google/gopacket"
	"github.com/google/gopacket/defrag/sctpdefrag"
	"github.com/google/gopacket/layers"
	"testing"
)

func TestDecodingBundledChunks(t *testing.T) {
	var tests = []struct {
		name        string
		description string // Description completes the sentence "Test decoding ...".
		data        []byte
		want        []gopacket.LayerType
	}{
		{
			name:        "SackData",
			description: "chunks bundle with DATA as the final chunk",
			data:        mustDecodeHexString("0300001003fe3c190000bb8000000000" + "00030017e153413e0000000100000012201e000300000000"),
			want:        []gopacket.LayerType{layers.LayerTypeSCTPSack, layers.LayerTypeSCTPData},
		},
		{
			name:        "DataSack",
			description: "chunks bundle with DATA as the first chunk",
			data:        mustDecodeHexString("00030017e153413e0000000100000012201e000300000000" + "0300001003fe3c190000bb8000000000"),
			want:        []gopacket.LayerType{layers.LayerTypeSCTPData, layers.LayerTypeSCTPSack},
		},
		{
			name:        "DataData",
			description: "a bundle of two DATA chunks",
			data:        mustDecodeHexString("00030017e153413e0000000100000012201e000300000000" + "00030017e153413e0000000100000012201e000300000000"),
			want:        []gopacket.LayerType{layers.LayerTypeSCTPData, layers.LayerTypeSCTPData},
		},
		{
			name:        "InitInitInitInit",
			description: "repeating INIT chunks (4 times)",
			data:        mustDecodeHexString("01000014e153413d0000bb800003000ae153413d" + "01000014e153413d0000bb800003000ae153413d" + "01000014e153413d0000bb800003000ae153413d" + "01000014e153413d0000bb800003000ae153413d"),
			want:        []gopacket.LayerType{layers.LayerTypeSCTPInit, layers.LayerTypeSCTPInit, layers.LayerTypeSCTPInit, layers.LayerTypeSCTPInit},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("Test decoding %v", tt.description)
			got := collectChunks(t, tt.data)
			if !compareLayerTypes(got, tt.want) {
				t.Errorf("Bundled chunks = %v, want %v", got, tt.want)
			}
		})
	}
}

// This function fails and stops the test if decoding fails. It should be called
// from a subtest, otherwise the main test will not proceed to the next testcase.
func collectChunks(t *testing.T, data []byte) []gopacket.LayerType {
	t.Helper()
	var chunks []gopacket.LayerType
	dataSize := len(data) // Used to identify the input data inside loop iterations.
	for len(data) != 0 {
		var bundle sctpdefrag.ChunkBundle
		err := bundle.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
		if err != nil {
			t.Fatalf("DecodeFromBytes(data[%d:]) failed: %v", dataSize-len(data), err)
		}
		chunks = append(chunks, bundle.LayerType())
		data = bundle.LayerPayload() // Continue decoding from the next chunk.
	}
	return chunks
}

// This function can be simplified with the generic slices.Equal when this module
// bumps to go1.18.
func compareLayerTypes(left, right []gopacket.LayerType) (equal bool) {
	if len(left) != len(right) {
		return false
	}
	for i, l := range left {
		if l != right[i] {
			return false
		}
	}
	return true
}

func mustDecodeHexString(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestDecodingUnalignedData(t *testing.T) {
	// This packet data contains 16 bytes for the chunk + 7 bytes of valid S1AP
	// payload (MMEConfigurationUpdateAcknowledge). This results in 23 bytes, but a
	// valid SCTP packet must contain 24 bytes.
	const packetData = "00030017e153413e0000000100000012201e0003000000"
	var chunks sctpdefrag.ChunkBundle
	err := chunks.DecodeFromBytes(mustDecodeHexString(packetData), gopacket.NilDecodeFeedback)
	if err == nil {
		t.Errorf("DecodeFromBytes() = nil, want a non-nil error")
		t.Log("The decoded chunk:\n", gopacket.LayerDump(&chunks))
	}
}

func TestDecodingPadding(t *testing.T) {}

func TestDecodingTruncatedData(t *testing.T) {
	// This DATA chunk header (first 16 bytes) indicates a payload of 7 bytes, but
	// we've truncated the last byte off the payload.
	const packetData = "00030017e153413e0000000100000012aabbccddeeff"
	var chunks sctpdefrag.ChunkBundle
	var truncated boolDecodeFeedback
	err := chunks.DecodeFromBytes(mustDecodeHexString(packetData), &truncated)
	if err != nil {
		t.Errorf("DecodeFromBytes() = %v", err)
	}
	if !truncated {
		t.Errorf("DecodeFromBytes did not consider the chunk truncated")
	}
}

type boolDecodeFeedback bool

func (t *boolDecodeFeedback) SetTruncated() {
	*t = true
}
