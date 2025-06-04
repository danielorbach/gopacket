package sctpdefrag_test

import (
	"encoding/hex"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/defrag/sctpdefrag"
	"github.com/google/gopacket/layers"
	"testing"
)

func ExampleChunkBundle() {
	// This packet contains an SCTP SACK chunk followed by an SCTP DATA chunk.
	//
	// The SACK chunk occupies 16 bytes, followed by 24 bytes of the DATA chunk. The
	// DATA chunk contains 16 bytes of header followed by 7 bytes of payload and 1
	// byte of padding.
	packetData := []byte{
		0x03, 0x00, 0x00, 0x10, 0x03, 0xfe, 0x3c, 0x19,
		0x00, 0x00, 0xbb, 0x80, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x03, 0x00, 0x17, 0xe1, 0x53, 0x41, 0x3e,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x12,
		0x20, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
	}

	// An sctpdefrag.ChunkBundle implements gopacket.DecodingLayer so it can be
	// decoded from a byte slice.
	var chunks sctpdefrag.ChunkBundle
	var offset int // Used to identify the input data inside loop iterations.
	// This loop resembles the decoding loop within gopacket.DecodingLayerParser. It
	// decodes the first portion of the data buffer and then continues decoding from
	// the next chunk.
	for len(packetData) != 0 {
		// DecodeFromBytes() is the main decoding function. When it returns a nil error,
		// the chunk has been decoded successfully and is now accessible via the Header,
		// Chunk and Layer functions.
		err := chunks.DecodeFromBytes(packetData, gopacket.NilDecodeFeedback)
		if err != nil {
			panic(err)
		}
		fmt.Printf("Found chunk %v at offset %v\n", chunks.LayerType(), offset)
		fmt.Println(gopacket.LayerDump(&chunks))
		// The LayerContents() function returns the raw bytes of the entire chunk,
		// including the payload carried by DATA chunks.
		offset += len(chunks.LayerContents())
		// The LayerPayload() function returns the raw bytes containing the next chunk
		// if there is any.
		packetData = chunks.LayerPayload()
	}

	// Output:
	// Found chunk SCTPSack at offset 0
	// SCTPSack	{Contents=[..16..] Payload=[..24..] Type=Sack Flags=0 Length=16 ActualLength=16 CumulativeTSNAck=66993177 AdvertisedReceiverWindowCredit=48000 NumGapACKs=0 NumDuplicateTSNs=0 GapACKs=[] DuplicateTSNs=[]}
	// 00000000  03 00 00 10 03 fe 3c 19  00 00 bb 80 00 00 00 00  |......<.........|
	//
	// Found chunk SCTPData at offset 16
	// SCTPData	{Contents=[..16..] Payload=[..7..] Type=Data Flags=3 Length=23 ActualLength=16 Unordered=false BeginFragment=true EndFragment=true TSN=3780329790 StreamId=0 StreamSequence=1 PayloadProtocol=S1AP}
	// 00000000  00 03 00 17 e1 53 41 3e  00 00 00 01 00 00 00 12  |.....SA>........|
	// 00000010  20 aa bb cc dd ee ff                              | ......|
}

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
