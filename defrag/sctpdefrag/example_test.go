package sctpdefrag_test

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/defrag/sctpdefrag"
	"github.com/google/gopacket/layers"
)

func ExampleChunksFrom() {
	// Performance-oriented parsing requires prior knowledge of the stack's layers.
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeLinuxSLL)
	// For this example this is quite easy, we know the entire packet in advance.
	//
	// However, users rarely know which SCTP chunks are present in any SCTP packet
	// because the standard supports bundling of multiple chunks into a single SCTP
	// packet. This means that an SCTP packet may contain any number of chunks,
	// allowing for multiple chunks of the same type.
	//
	// For this reason, this package provides DecodingLayers that support arbitrary
	// occurrences of the same chunk type.
	var (
		link      layers.LinuxSLL
		network   layers.IPv4
		transport layers.SCTP
		chunks    gopacket.Payload
	)
	parser.AddDecodingLayer(&link)
	parser.AddDecodingLayer(&network)
	parser.AddDecodingLayer(&transport)
	parser.AddDecodingLayer(&chunks)

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

	// The SCTP payload contains chunks, which we can decode further using the
	// ChunksFrom function.
	for i, chunk := range sctpdefrag.ChunksFrom(chunks) {
		// Note that each chunk variable is valid after the loop iteration completes.
		// That is, callers may store the layer and reference it even after the entire
		// for-loop completes.
		//
		// This implies that ChunksFrom allocates a new value for every chunk it
		// encounters.
		fmt.Printf("Chunk no.%v: %v\n", i+1, gopacket.LayerString(chunk))
	}

	// Output:
	// Decoded layers: [Linux SLL IPv4 SCTP Payload]
	// Decoded link layer: Linux SLL	{Contents=[..16..] Payload=[..72..] PacketType=outgoing AddrLen=6 Addr=2c:a5:39:00:1f:36 EthernetType=IPv4 AddrType=16}
	// Decoded network layer: IPv4	{Contents=[..20..] Payload=[..52..] Version=4 IHL=5 TOS=0 Length=72 Id=0 Flags=DF FragOffset=0 TTL=64 Protocol=SCTP Checksum=9546 SrcIP=10.53.0.25 DstIP=10.43.0.112 Options=[] Padding=[]}
	// Decoded transport layer: SCTP	{Contents=[..12..] Payload=[..40..] SrcPort=36412(s1-control) DstPort=36412(s1-control) VerificationTag=66993176 Checksum=3540262820}
	// Chunk no.1: SCTPSack	{Contents=[..16..] Payload=[..24..] Type=Sack Flags=0 Length=16 ActualLength=16 CumulativeTSNAck=66993177 AdvertisedReceiverWindowCredit=48000 NumGapACKs=0 NumDuplicateTSNs=0 GapACKs=[] DuplicateTSNs=[]}
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

// This example demonstrates how ChunksFrom handles decoding failures in SCTP
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
func ExampleChunksFrom_decodeFailure() {
	// The opening section is fairly standard, this example focuses on how ChunksFrom
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
	// When ChunksFrom encounters a chunk that it fails to decode, it invokes the
	// yield callback one last time with a DecodeChunkFailure layer.
	for i, chunk := range sctpdefrag.ChunksFrom(badPacketPayload) {
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
	// When ChunksFrom encounters an error, it yields to the loop one last time with
	// an ErrorLayer, whose LayerType is gopacket.LayerTypeDecodeFailure.
	for _, chunk := range sctpdefrag.ChunksFrom(unpaddedDataChunk) {
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
