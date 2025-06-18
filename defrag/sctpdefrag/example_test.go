package sctpdefrag_test

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/defrag/sctpdefrag"
	"github.com/google/gopacket/layers"
)

// Example_iteratingBundledChunks demonstrates two patterns for iterating over
// bundled SCTP chunks: the simpler Unbundle (allocates per chunk) and the more
// efficient BundleContainer (reuses layers).
func Example_iteratingBundledChunks() {
	// Performance-oriented parsing requires prior knowledge of the stack's layers.
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeLinuxSLL)

	// For this example, we know the packet structure in advance. However, SCTP
	// supports bundling multiple chunks into a single packet, which means we need
	// special handling for the SCTP payload.
	var (
		link      layers.LinuxSLL
		network   layers.IPv4
		transport layers.SCTP
		bundle    sctpdefrag.BundleContainer
	)
	parser.AddDecodingLayer(&link)
	parser.AddDecodingLayer(&network)
	parser.AddDecodingLayer(&transport)
	parser.AddDecodingLayer(&bundle)

	// After registering the layers, we can decode the packet data.
	var decoded []gopacket.LayerType
	err := parser.DecodeLayers(ExamplePacketData, &decoded)
	if err != nil {
		panic(err)
	}

	fmt.Println("Decoded layers:", decoded)
	fmt.Println("Decoded link layer:", gopacket.LayerString(&link))
	fmt.Println("Decoded network layer:", gopacket.LayerString(&network))
	fmt.Println("Decoded transport layer:", gopacket.LayerString(&transport))

	// Unbundle parses the SCTP packet payload, one chunk at a time, returning the
	// next decoded layer per iteration. Each chunk is allocated as a new layer
	// object, making it safe for use after the next iteration (or after the loop
	// altogether) but more memory intensive.
	//
	// Use this pattern when simplicity is more important than performance.
	//
	fmt.Println("\n=== Pattern 1: Unbundle (allocates per chunk) ===")
	// The SCTP payload is also accessible by adding a gopacket.Payload layer to the
	// DecodingLayerParser, or by getting the LayerContents of the BundleContainer.
	// In this example we just access the payload of the SCTP layer directly.
	for i, chunk := range sctpdefrag.Unbundle(transport.LayerPayload()) {
		fmt.Printf("Chunk no.%d: %s\n", i+1, gopacket.LayerString(chunk))
	}

	// BundleContainer is a more efficient pattern that reuses layer objects for
	// parsing SCTP chunks. Instead of allocating new objects for each chunk, it
	// shifts the responsibility of allocating chunk layers to callers, facilitating
	// reuse of the same layer type. As a result, it is also more efficient in not
	// decoding irrelevant chunks.
	//
	// The BundleContainer pattern is ideal for high-performance scenarios where memory
	// allocation needs to be minimised. However, note that the returned chunks slice
	// is only valid until the next call to DecodeFromBytes, as the underlying memory
	// will be reused.
	//
	// This approach is more verbose but provides the best performance for
	// applications that process many packets rapidly.
	fmt.Println("\n=== Pattern 2: BundleContainer (reuses layers) ===")
	// Chunks() returns a reused slice that is valid until the next call to
	// DecodeFromBytes. By the time DecodingLayerParser.DecodeLayers returns with a
	// nil error, the entire SCTP payload will have been decoded all chunks
	// successfully.
	chunkTypes := make([]layers.SCTPChunkType, len(bundle.Chunks()))
	for i, chunk := range bundle.Chunks() {
		chunkTypes[i] = chunk.Type
	}
	fmt.Printf("Found %d chunks: %v\n", len(chunkTypes), chunkTypes)

	// With the BundleContainer we get the change to pre-allocate layers that we'll
	// reuse for decoding.
	//
	// In this example, we're only interested in DATA chunks.
	var (
		dataChunk layers.SCTPData
	)
	// Then, we iterate through chunks efficiently using the exposed slice.
	//
	// For every chunk-type of interest, we know the appropriate layer-type at
	// coding-time. We then use the pre-allocated layer to DecodeFromBytes for each
	// SCTP chunk in the bundle.
	for i, chunk := range bundle.Chunks() {
		switch chunk.Type {
		case layers.SCTPChunkTypeData:
			// Decode the full DATA chunk using the chunk's raw bytes.
			if err := dataChunk.DecodeFromBytes(chunk.LayerContents(), gopacket.NilDecodeFeedback); err != nil {
				fmt.Printf("Failed to decode DATA chunk no.%d: %v\n", i+1, err)
				continue
			}
			fmt.Printf("Chunk no.%d: %s\n", i+1, gopacket.LayerString(&dataChunk))
		default:
			// For unknown or unhandled chunk types, we already have basic info from
			// the SCTPChunk.
			fmt.Printf("Chunk no.%d: %s\n", i+1, sctpdefrag.FormatChunkHeader(chunk))
		}
	}

	// Output:
	// Decoded layers: [Linux SLL IPv4 SCTP Payload]
	// Decoded link layer: Linux SLL	{Contents=[..16..] Payload=[..72..] PacketType=outgoing AddrLen=6 Addr=2c:a5:39:00:1f:36 EthernetType=IPv4 AddrType=16}
	// Decoded network layer: IPv4	{Contents=[..20..] Payload=[..52..] Version=4 IHL=5 TOS=0 Length=72 Id=0 Flags=DF FragOffset=0 TTL=64 Protocol=SCTP Checksum=9546 SrcIP=10.53.0.25 DstIP=10.43.0.112 Options=[] Padding=[]}
	// Decoded transport layer: SCTP	{Contents=[..12..] Payload=[..40..] SrcPort=36412(s1-control) DstPort=36412(s1-control) VerificationTag=66993176 Checksum=3540262820}
	//
	// === Pattern 1: Unbundle (allocates per chunk) ===
	// Chunk no.1: SCTPSack	{Contents=[..16..] Payload=[..24..] Type=Sack Flags=0 Length=16 ActualLength=16 CumulativeTSNAck=66993177 AdvertisedReceiverWindowCredit=48000 NumGapACKs=0 NumDuplicateTSNs=0 GapACKs=[] DuplicateTSNs=[]}
	// Chunk no.2: SCTPData	{Contents=[..24..] Payload=[] Type=Data Flags=3 Length=23 ActualLength=24 Unordered=false BeginFragment=true EndFragment=true TSN=3780329790 StreamId=0 StreamSequence=1 PayloadProtocol=S1AP UserData=[..7..]}
	//
	// === Pattern 2: BundleContainer (reuses layers) ===
	// Found 2 chunks: [Sack Data]
	// Chunk no.1: SCTPChunk	{Contents=[..16..] Payload=[] Type=Sack, Flags=0x00, Length=16, ActualLength=16}
	// Chunk no.2: SCTPData	{Contents=[..24..] Payload=[] Type=Data Flags=3 Length=23 ActualLength=24 Unordered=false BeginFragment=true EndFragment=true TSN=3780329790 StreamId=0 StreamSequence=1 PayloadProtocol=S1AP UserData=[..7..]}
}

// This packet contains an SCTP packet with two chunks: SACK followed by DATA.
var ExamplePacketData = []byte{
	// Linux Cooked Capture (SLL): 16 bytes.
	0x00, 0x04, 0x00, 0x10, 0x00, 0x06, 0x2c, 0xa5,
	0x39, 0x00, 0x1f, 0x36, 0x00, 0x00, 0x08, 0x00,
	// IP(v4) header: 20 bytes.
	0x45, 0x00, 0x00, 0x48, 0x00, 0x00, 0x40, 0x00,
	0x40, 0x84, 0x25, 0x4a, 0x0a, 0x35, 0x00, 0x19,
	0x0a, 0x2b, 0x00, 0x70,
	// SCTP header: 12 bytes.
	0x8e, 0x3c, 0x8e, 0x3c, 0x03, 0xfe, 0x3c, 0x18,
	0xd3, 0x04, 0x1f, 0xa4,
	// SACK chunk: 16 bytes.
	0x03, 0x00, 0x00, 0x10, 0x03, 0xfe, 0x3c, 0x19,
	0x00, 0x00, 0xbb, 0x80, 0x00, 0x00, 0x00, 0x00,
	// DATA chunk: 16 bytes chunk header + 7 bytes payload + 1 byte padding.
	0x00, 0x03, 0x00, 0x17, 0xe1, 0x53, 0x41, 0x3e,
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x12,
	0x20, 0x1e, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
}

// This example demonstrates how Unbundle handles decoding failures in SCTP
// packets: by yielding to the loop one last time with an error layer (of type
// sctpdefrag.DecodeChunkFailure).
//
// It demonstrates two common invalid packets that fail to decode: truncated and
// unpadded.
//
// The chunk types that may require padding are: DATA, INIT, INIT_ACK,
// COOKIE_ECHO, HEARTBEAT_ACK, and ERROR. This example uses a DATA chunk to show
// the point.
//
// The other chunk types have a fixed size (no variable length fields mean, by
// definition, no padding), so any missing bytes are necessarily deducted from
// the chunk itself, not padding.
//
// As a reminder, the SCTP specification mandates that all chunks must align to a
// 4-byte boundary. As such, variable-length chunks must be padded with zeroes to
// fill up to 3 bytes, while fixed-length chunks already have aligned sizes.
func ExampleUnbundle_decodeFailure() {
	// The opening section is fairly standard, this example focuses on how Unbundle
	// handles decoding failures, so we will skip the introduction and just use the
	// badPacketPayload as the payload of an SCTP packet.
	var badPacketPayload = []byte{
		// SACK chunk: 16 bytes.
		0x03, 0x00, 0x00, 0x10, 0x03, 0xfe, 0x3c, 0x19,
		0x00, 0x00, 0xbb, 0x80, 0x00, 0x00, 0x00, 0x00,
		// DATA chunk: 16 bytes chunk header + 7 bytes payload + 1 byte padding.
		0x00, 0x03, 0x00, 0x17, 0xe1, 0x53, 0x41, 0x3e,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x12,
		0x20, 0x1e, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
		// BAD chunk: 4 bytes out of 17 (a truncated chunk causes decoding to fail).
		0x00, 0x03, 0x00, 0x11,
	}
	fmt.Println("Bad packet payload:")
	// When Unbundle encounters a chunk that it fails to decode, it invokes the yield
	// callback one last time with a DecodeChunkFailure layer.
	for i, chunk := range sctpdefrag.Unbundle(badPacketPayload) {
		fmt.Printf("Chunk no.%v: %v\n", i+1, gopacket.LayerString(chunk))
	}

	// This packet contains a DATA chunk with 16 bytes of header plus 7 bytes of
	// payload, totalling 23 bytes. However, SCTP requires all chunks to be padded to
	// 4-byte boundaries, which means the DATA chunk should be 24 bytes long.
	var unpaddedDataChunk = []byte{
		0x00, 0x03, 0x00, 0x17, 0xe1, 0x53, 0x41, 0x3e,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x12,
		0x20, 0x1e, 0x00, 0x03, 0x00, 0x00, 0x00,
	}
	fmt.Printf("DATA chunk size: %d bytes (should be 24 for proper padding)\n", len(unpaddedDataChunk))
	// When Unbundle encounters an error, it yields to the loop one last time with an
	// ErrorLayer, whose LayerType is gopacket.LayerTypeDecodeFailure.
	for _, chunk := range sctpdefrag.Unbundle(unpaddedDataChunk) {
		fmt.Println(gopacket.LayerDump(chunk))
	}

	// Output:
	// Bad packet payload:
	// Chunk no.1: SCTPSack	{Contents=[..16..] Payload=[..28..] Type=Sack Flags=0 Length=16 ActualLength=16 CumulativeTSNAck=66993177 AdvertisedReceiverWindowCredit=48000 NumGapACKs=0 NumDuplicateTSNs=0 GapACKs=[] DuplicateTSNs=[]}
	// Chunk no.2: SCTPData	{Contents=[..24..] Payload=[0, 3, 0, 17] Type=Data Flags=3 Length=23 ActualLength=24 Unordered=false BeginFragment=true EndFragment=true TSN=3780329790 StreamId=0 StreamSequence=1 PayloadProtocol=S1AP UserData=[..7..]}
	// Chunk no.3: DecodeFailure	decoding SCTP chunk from bytes: invalid SCTP chunk data: not enough bytes (truncated=true)
	// DATA chunk size: 23 bytes (should be 24 for proper padding)
	// DecodeFailure	decoding SCTP chunk from bytes: invalid SCTP chunk data: not enough padding (truncated=false)
	// 00000000  00 03 00 17 e1 53 41 3e  00 00 00 01 00 00 00 12  |.....SA>........|
	// 00000010  20 1e 00 03 00 00 00                              | ......|
}
