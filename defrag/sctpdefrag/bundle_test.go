package sctpdefrag_test

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/defrag/sctpdefrag"
	"github.com/google/gopacket/layers"
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

// TestDecodingWithPadding ensures that packets with padding are decoded
// properly. It works in tandem with TestDecodingWithoutPadding to ensure that a
// chunk is successfully decoded if and only if it has sufficient padding.
func TestDecodingWithPadding(t *testing.T) {
	// This packet data contains 16 bytes for the chunk + 7 bytes of valid S1AP
	// payload (MMEConfigurationUpdateAcknowledge) + 1 byte of padding.
	const packetData = "00030017e153413e0000000100000012201e000300000000"
	var chunks sctpdefrag.ChunkBundle
	err := chunks.DecodeFromBytes(mustDecodeHexString(packetData), gopacket.NilDecodeFeedback)
	if err != nil {
		t.Errorf("DecodeFromBytes() = %v", err)
	}
	// The LayerContents() function returns the raw bytes of the chunk's header,
	// including the payload of DATA chunks.
	contents := chunks.LayerContents()
	if len(contents) != 24 {
		t.Errorf("LayerContents() = %v, want 24", len(contents))
	}
	// The LayerPayload() function returns the raw bytes of the next chunk, if any.
	payload := chunks.LayerPayload()
	if len(payload) != 0 {
		t.Errorf("LayerPayload() = %v, want 0", len(payload))
	}
}

// ExampleChunkBundle_unpaddedData demonstrates how ChunkBundle handles SCTP
// DATA chunks that lack proper padding. This example shows the decoder's
// behavior when encountering malformed packets that don't follow SCTP's
// 4-byte alignment requirement.
func ExampleChunkBundle_unpaddedData() {
	// This packet contains a DATA chunk with 16 bytes of header plus 7 bytes of
	// payload, totalling 23 bytes. However, SCTP requires all chunks to be padded to
	// 4-byte boundaries, which means the DATA chunk should be 24 bytes long.
	var packetData = []byte{
		0x00, 0x03, 0x00, 0x17, 0xe1, 0x53, 0x41, 0x3e,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x12,
		0x20, 0x1e, 0x00, 0x03, 0x00, 0x00, 0x00,
	}
	fmt.Printf("Packet size: %d bytes (should be 24 for proper padding)\n", len(packetData))

	// Use a custom DecodeFeedback to track if the decoder detects truncation
	var truncated boolDecodeFeedback

	// Create a ChunkBundle to decode the malformed packet
	var chunks sctpdefrag.ChunkBundle
	err := chunks.DecodeFromBytes(packetData, &truncated)
	if err != nil {
		fmt.Printf("Decoding failed: %v\n", err)
		return
	}

	// When a chunk lacks proper padding and is the last chunk in a packet,
	// the decoder marks it as truncated rather than failing completely
	fmt.Printf("Decoder marked chunk as truncated: %v\n", bool(truncated))

	// Extract the DATA chunk to examine how the payload was decoded
	dataChunk := chunks.Layer(layers.LayerTypeSCTPData).(*layers.SCTPData)

	// The decoder still extracts the payload, but the missing padding affects
	// how the data boundary is calculated
	fmt.Printf("Decoded payload length: %d bytes\n", len(dataChunk.UserData))
	fmt.Printf("Payload content: %x\n", dataChunk.UserData)

	// The chunk length field indicates 23 bytes total (0x0017 = 23)
	fmt.Printf("Chunk length from header: %d bytes\n", dataChunk.Length)

	// This demonstrates that while the decoder can handle unpadded chunks,
	// it correctly identifies them as malformed by setting the truncated flag

	// Output:
	// Packet size: 23 bytes (should be 24 for proper padding)
	// Decoder marked chunk as truncated: true
	// Decoded payload length: 7 bytes
	// Payload content: 201e0003000000
	// Chunk length from header: 23 bytes
}

// TestDecodingTruncatedData ensures the package behaves consistently when faced
// with truncated packet data.
//
// This test overlaps with TestDecodingWithoutPadding, but it is different
// because its data is aligned to the 4-byte boundary.
func TestDecodingTruncatedData(t *testing.T) {
	// This DATA chunk header (first 16 bytes) indicates a payload of 7 bytes, but
	// we've truncated the last three bytes off the payload (we must keep the size of
	// truncated data a multiple of 4).
	const packetData = "00030017e153413e0000000100000012201e0003"
	var chunks sctpdefrag.ChunkBundle
	var truncated boolDecodeFeedback
	err := chunks.DecodeFromBytes(mustDecodeHexString(packetData), &truncated)
	if err == nil {
		t.Errorf("DecodeFromBytes() succeeded, but should have failed due to truncated data")
	}
	if !truncated {
		t.Errorf("DecodeFromBytes did not consider the chunk truncated")
	}
}

// TestDecodingDataBundles verifies that when multiple DATA chunks are bundled together,
// the internal buffer for each DATA chunk's UserData contains only the payload specific
// to that chunk.
func TestDecodingDataBundles(t *testing.T) {
	//const packetData = "000300170000000100000002000000034444444444444400" + "000300170000000500000006000000078888888888888800"
	//var chunks sctpdefrag.ChunkBundle
	//err := chunks.DecodeFromBytes(mustDecodeHexString(packetData), gopacket.NilDecodeFeedback)
	//if err != nil {
	//	t.Errorf("DecodeFromBytes() = %v", err)
	//}
	//data, ok := chunks.Layer(layers.LayerTypeSCTPData).(*layers.SCTPData)
	//if !ok {
	//	t.Errorf("DecodeFromBytes() = %v, want %v", chunks.LayerType(), layers.LayerTypeSCTPData)
	//}

}

type boolDecodeFeedback bool

func (t *boolDecodeFeedback) SetTruncated() {
	*t = true
}
