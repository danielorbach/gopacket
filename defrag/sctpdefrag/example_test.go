package sctpdefrag_test

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/defrag/sctpdefrag"
	"github.com/google/gopacket/layers"
)

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
	sctpdefrag.ChunksFrom(chunks)(func(i int, chunk gopacket.Layer) bool {
		fmt.Printf("Chunk no.%v: %v\n", i+1, gopacket.LayerString(chunk))
		return true
	})

	// Output:
	// Decoded layers: [Linux SLL IPv4 SCTP Payload]
	// Decoded link layer: Linux SLL	{Contents=[..16..] Payload=[..72..] PacketType=outgoing AddrLen=6 Addr=2c:a5:39:00:1f:36 EthernetType=IPv4 AddrType=16}
	// Decoded network layer: IPv4	{Contents=[..20..] Payload=[..52..] Version=4 IHL=5 TOS=0 Length=72 Id=0 Flags=DF FragOffset=0 TTL=64 Protocol=SCTP Checksum=9546 SrcIP=10.53.0.25 DstIP=10.43.0.112 Options=[] Padding=[]}
	// Decoded transport layer: SCTP	{Contents=[..12..] Payload=[..40..] SrcPort=36412(s1-control) DstPort=36412(s1-control) VerificationTag=66993176 Checksum=3540262820}
	// Chunk no.1: SCTPSack	{Contents=[..16..] Payload=[..24..] Type=Sack Flags=0 Length=16 ActualLength=16 CumulativeTSNAck=66993177 AdvertisedReceiverWindowCredit=48000 NumGapACKs=0 NumDuplicateTSNs=0 GapACKs=[] DuplicateTSNs=[]}
	// Chunk no.2: SCTPData	{Contents=[..24..] Payload=[] Type=Data Flags=3 Length=23 ActualLength=24 Unordered=false BeginFragment=true EndFragment=true TSN=3780329790 StreamId=0 StreamSequence=1 PayloadProtocol=S1AP UserData=[..7..]}
}

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

	// When ChunksFrom encounters a chunk that it fails to decode, it invokes the
	// yield callback one last time with a DecodeChunkFailure layer.
	sctpdefrag.ChunksFrom(badPacketPayload)(func(i int, chunk gopacket.Layer) bool {
		fmt.Printf("Chunk no.%v: %v\n", i+1, gopacket.LayerString(chunk))
		return true
	})

	// Output:
	// Chunk no.1: SCTPSack	{Contents=[..16..] Payload=[..28..] Type=Sack Flags=0 Length=16 ActualLength=16 CumulativeTSNAck=66993177 AdvertisedReceiverWindowCredit=48000 NumGapACKs=0 NumDuplicateTSNs=0 GapACKs=[] DuplicateTSNs=[]}
	// Chunk no.2: SCTPData	{Contents=[..24..] Payload=[0, 3, 0, 17] Type=Data Flags=3 Length=23 ActualLength=24 Unordered=false BeginFragment=true EndFragment=true TSN=3780329790 StreamId=0 StreamSequence=1 PayloadProtocol=S1AP UserData=[..7..]}
	// Chunk no.3: DecodeFailure	decoding SCTP chunk from bytes: invalid SCTP chunk data: not enough bytes
}

func Example_chunkSelector() {
	// Performance-oriented parsing requires prior knowledge of the stack's layers.
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeLinuxSLL)
	// For this example this is quite easy, we know the entire packet in advance.
	//
	// However, users rarely know which SCTP chunks are present in any SCTP packet
	// because the standard supports bundling of multiple chunks into a single SCTP
	// packet. As a result, callers may want to ignore some less interesting chunk
	// types.
	//
	// For this reason, this package provides a DecodingLayer that discard most SCTP
	// chunks: SCTPChunkSkipper.
	var (
		link      = new(layers.LinuxSLL)
		network   = new(layers.IPv4)
		transport = new(layers.SCTP)
		data      = new(layers.SCTPData)
	)
	parser.AddDecodingLayer(link)
	parser.AddDecodingLayer(network)
	parser.AddDecodingLayer(transport)
	// We can use the layers.SCTPChunkSelector to selectively decode SCTP chunks
	// based on their type. Callers may choose Strict mode to prevent fail fast when
	// attempting to decode unknown chunk types.
	parser.AddDecodingLayer(&layers.SCTPChunkSelector{Strict: true})
	// We can use the sctpdefrag.SCTPChunkSkipper to discard irrelevant chunks. We must
	// exclude interesting chunk types that we do want to decode.
	//
	// Though it is possible to achieve the same result by adding the zero
	// sctpdefrag.SCTPChunkSkipper, if and only if we also add the DecodingLayers for the
	// interesting chunk types AFTER adding that skipper. Any of the afterwards calls
	// to AddDecodingLayer would overwrite the DecodingLayer set by previous ones.
	// Nonetheless, stating the interesting layers explicitly is clearer.
	parser.AddDecodingLayer(sctpdefrag.DiscardSCTPChunksExcept(layers.SCTPChunkTypeData))
	parser.AddDecodingLayer(data)

	// After registering the layers, we can decode the packet data.
	var decoded []gopacket.LayerType
	err := parser.DecodeLayers(ExamplePacketData, &decoded)
	if err != nil {
		panic(err)
	}
	fmt.Println("Decoded layers:", decoded)
	fmt.Println("Decoded link layer:", gopacket.LayerString(link))
	fmt.Println("Decoded network layer:", gopacket.LayerString(network))
	fmt.Println("Decoded transport layer:", gopacket.LayerString(transport))
	fmt.Println("Decoded DATA chunk:", gopacket.LayerString(data))

	// Output:
	// Decoded layers: [Linux SLL IPv4 SCTP Payload SCTPSack Payload SCTPData]
	// Decoded link layer: Linux SLL	{Contents=[..16..] Payload=[..72..] PacketType=outgoing AddrLen=6 Addr=2c:a5:39:00:1f:36 EthernetType=IPv4 AddrType=16}
	// Decoded network layer: IPv4	{Contents=[..20..] Payload=[..52..] Version=4 IHL=5 TOS=0 Length=72 Id=0 Flags=DF FragOffset=0 TTL=64 Protocol=SCTP Checksum=9546 SrcIP=10.53.0.25 DstIP=10.43.0.112 Options=[] Padding=[]}
	// Decoded transport layer: SCTP	{Contents=[..12..] Payload=[..40..] SrcPort=36412(s1-control) DstPort=36412(s1-control) VerificationTag=66993176 Checksum=3540262820}
	// Decoded DATA chunk: SCTPData	{Contents=[..24..] Payload=[] Type=Data Flags=3 Length=23 ActualLength=24 Unordered=false BeginFragment=true EndFragment=true TSN=3780329790 StreamId=0 StreamSequence=1 PayloadProtocol=S1AP UserData=[..7..]}
}
