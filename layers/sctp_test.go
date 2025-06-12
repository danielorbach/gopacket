// Copyright 2019 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file in the root of the source tree.

package layers

import (
	"fmt"
	"testing"

	"github.com/google/gopacket"
)

func Example_sctpDecodingLayer() {
	// This packet contains an SCTP packet with several chunks, each showcasing a
	// nuance of using the DecodingLayer API with SCTP packets.
	packetData := []byte{
		// Linux Cooked Capture (SLL): 16 bytes.
		0x00, 0x04, 0x00, 0x10, 0x00, 0x06, 0x2c, 0xa5,
		0x39, 0x00, 0x1f, 0x36, 0x00, 0x00, 0x08, 0x00,
		// IP(v4) header: 20 bytes.
		0x45, 0x00, 0x00, 0x68, 0x00, 0x00, 0x40, 0x00,
		0x40, 0x84, 0x25, 0x2a, 0x0a, 0x35, 0x00, 0x19,
		0x0a, 0x2b, 0x00, 0x70,
		// SCTP header: 12 bytes.
		0x8e, 0x3c, 0x8e, 0x3c, 0x03, 0xfe, 0x3c, 0x18,
		0x3f, 0xd6, 0xde, 0xfa,
		// SACK chunk: 16 bytes.
		0x03, 0x00, 0x00, 0x10, 0xe1, 0x53, 0x41, 0x3d,
		0x00, 0x00, 0x27, 0x10, 0x00, 0x00, 0x00, 0x00,
		// UNKNOWN chunk: 16 bytes of unknown format.
		0xfe, 0x00, 0x00, 0x10, 0xde, 0xad, 0xbe, 0xef,
		0xB1, 0x6B, 0x00, 0xB5, 0xF0, 0x0D, 0xBA, 0xBE,
		// DATA chunk: 16 bytes chunk header + 7 bytes payload + 1 byte padding.
		0x00, 0x03, 0x00, 0x17, 0xe1, 0x53, 0x41, 0x3e,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x12,
		0x20, 0x1e, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
		// SACK chunk: 16 bytes.
		0x03, 0x00, 0x00, 0x10, 0x03, 0xfe, 0x3c, 0x19,
		0x00, 0x00, 0xbb, 0x80, 0x00, 0x00, 0x00, 0x00,
	}

	// Performance-oriented parsing requires prior knowledge of the stack's layers.
	//
	// Luckily, this package provides DecodingLayers that provide access to decoded
	// SCTP chunks.
	parser := gopacket.NewDecodingLayerParser(LayerTypeLinuxSLL)
	// For this example this is quite easy, we know the entire packet in advance.
	//
	// Unfortunately, users rarely know which SCTP chunks are present in any SCTP
	// packet and the standard supports bundling of multiple chunks into a single
	// SCTP packet. This means that an SCTP packet may contain any number of chunks,
	// allowing for multiple chunks of the same type.
	//
	// Fortunately, most SCTP packets contain at most a single occurrence of any
	// chunk type. This example shows how to access those interesting chunks by
	// cherry-picking the DATA chunk while ignoring the SACK chunk.
	var (
		link      LinuxSLL
		network   IPv4
		transport SCTP
		data      SCTPData
		unknown   SCTPUnknownChunkType
	)
	// We register the layers in the order they appear in the packet, though this is
	// not strictly necessary.
	parser.AddDecodingLayer(&link)
	parser.AddDecodingLayer(&network)
	parser.AddDecodingLayer(&transport)
	// The SCTPChunkSelector is a special DecodingLayer that allows us to selectively
	// decode SCTP chunks based on their type. This layer can decode Payload layers,
	// which are what SCTP reports as the next layer.
	parser.AddDecodingLayer(&SCTPChunkSelector{})
	// Though uncommon, you may encounter extension chunks that we don't know how to
	// decode. This does not necessarily block decoding. By providing a DecodingLayer
	// that can decode LayerTypeSCTPUnknownChunkType, these chunks are decoded as
	// opaque blocs, and processing moves on uninterrupted.
	parser.AddDecodingLayer(&unknown)
	// In this example we are interested in DATA chunks, so we must supply the parser
	// with an allocated layer to hold decoded values.
	parser.AddDecodingLayer(&data)
	// To skip uninteresting chunk types, add the appropriate layers as a discarded
	// variable.
	parser.AddDecodingLayer(&SCTPSack{})

	// After registering the layers, we can decode the packet data.
	var decoded []gopacket.LayerType
	err := parser.DecodeLayers(packetData, &decoded)
	if err != nil {
		panic(err)
	}
	fmt.Println("Decoded layers:", decoded)
	fmt.Println()
	fmt.Println("Decoded DATA chunk:", gopacket.LayerDump(&data))
	fmt.Println("Decoded UNKNOWN chunk:", gopacket.LayerDump(&unknown))

	// Output:
	// Decoded layers: [Linux SLL IPv4 SCTP Payload SCTPSack Payload SCTPUnknownChunkType Payload SCTPData Payload SCTPSack]
	//
	// Decoded DATA chunk: SCTPData	{Contents=[..24..] Payload=[..16..] Type=Data Flags=3 Length=23 ActualLength=24 Unordered=false BeginFragment=true EndFragment=true TSN=3780329790 StreamId=0 StreamSequence=1 PayloadProtocol=S1AP UserData=[..7..]}
	// 00000000  00 03 00 17 e1 53 41 3e  00 00 00 01 00 00 00 12  |.....SA>........|
	// 00000010  20 1e 00 03 00 00 00 00                           | .......|
	//
	// Decoded UNKNOWN chunk: SCTPUnknownChunkType	{Contents=[..16..] Payload=[..40..] Type=UnknownSCTPChunkType Flags=0 Length=16 ActualLength=16}
	// 00000000  fe 00 00 10 de ad be ef  b1 6b 00 b5 f0 0d ba be  |.........k......|
}

// TestDecodingSCTP verifies the decoding of SCTP packets by successfully
// building a gopacket.Packet, reserializing its layers, and comparing the output
// with the original data.
//
// More exemplar packets can be found in the Wireshark sample captures:
// <https://wiki.wireshark.org/SampleCaptures#stream-control-transmission-protocol-sctp>.
func TestDecodingSCTPChunks(t *testing.T) {
	var packetTests = []struct {
		name string
		data []byte
		want []gopacket.LayerType
	}{
		{name: "INIT", data: sctpTestPacketInit, want: []gopacket.LayerType{LayerTypeSCTP, LayerTypeSCTPInit}},
		{name: "INIT_ACK", data: sctpTestPacketInitAck, want: []gopacket.LayerType{LayerTypeSCTP, LayerTypeSCTPInitAck}},
		{name: "COOKIE_ECHO", data: sctpTestPacketCookieEcho, want: []gopacket.LayerType{LayerTypeSCTP, LayerTypeSCTPCookieEcho}},
		{name: "COOKIE_ACK", data: sctpTestPacketCookieAck, want: []gopacket.LayerType{LayerTypeSCTP, LayerTypeSCTPCookieAck}},
		{name: "SACK", data: sctpTestPacketSack, want: []gopacket.LayerType{LayerTypeSCTP, LayerTypeSCTPSack}},
		{name: "DATA", data: sctpTestPacketData, want: []gopacket.LayerType{LayerTypeSCTP, LayerTypeSCTPData}},
		{name: "HEARTBEAT", data: sctpTestPacketHeartbeat, want: []gopacket.LayerType{LayerTypeSCTP, LayerTypeSCTPHeartbeat}},
		{name: "HEARTBEAT_ACK", data: sctpTestPacketHeartbeatAck, want: []gopacket.LayerType{LayerTypeSCTP, LayerTypeSCTPHeartbeatAck}},
		{name: "SHUTDOWN|ACK|COMPLETE", data: sctpTestPacketShutdowns, want: []gopacket.LayerType{LayerTypeSCTP, LayerTypeSCTPShutdown, LayerTypeSCTPShutdownAck, LayerTypeSCTPShutdownComplete}},
		// The following chunk types are omitted because I haven't captured them.
		//{name: "ABORT", data: sctpTestPacketAbort},
		//{name: "ERROR", data: sctpTestPacketError},
		{name: "Bundling", data: sctpTestBundledPacket, want: []gopacket.LayerType{LayerTypeSCTP, LayerTypeSCTPSack, LayerTypeSCTPData}},
	}

	for _, tt := range packetTests {
		t.Run(tt.name, func(t *testing.T) {
			// First, we should successfully decode the SCTP packet.
			p := gopacket.NewPacket(tt.data, LayerTypeSCTP, gopacket.NoCopy)
			if l := p.ErrorLayer(); l != nil {
				t.Fatalf("NewPacket: %v", l.Error())
			}

			// Then, we verify that the packet contains the expected SCTP layer and chunks.
			checkLayers(p, tt.want, t)

			// Finally, we serialise it back to network bytes, comparing to the original data
			// that was captured.
			opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
			testSerializationWithOpts(t, p, tt.data, opts)
		})
	}

	t.Run("UnknownChunkType", func(t *testing.T) {
		// This package exposes the SCTPChunkTypeMetadata enum that defines how each
		// chunk-type is decoded. By default, unknown chunk types don't have a custom
		// Decoder, so decoding halts and considers them an error.
		defer func() { SCTPChunkTypeMetadata[0xff].DecodeWith = nil }()
		SCTPChunkTypeMetadata[0xff].DecodeWith = DecodeSCTPChunkTypeUnknown

		// First, we should successfully decode the SCTP packet.
		p := gopacket.NewPacket(sctpTestPacketUnknown, LayerTypeSCTP, gopacket.NoCopy)

		// Then, we verify that the packet contains the expected SCTP layer and chunks.
		want := []gopacket.LayerType{LayerTypeSCTP, LayerTypeSCTPUnknownChunkType, gopacket.LayerTypeDecodeFailure}
		checkLayers(p, want, t)

		// Finally, we serialise it back to network bytes, comparing to the original data
		// that was captured.
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		testSerializationWithOpts(t, p, sctpTestPacketUnknown, opts)
	})
}

// Packet with an INIT chunk (SCTPInit):
//
//	Stream Control Transmission Protocol, Src Port: 36412 (36412), Dst Port: 36412 (36412)
//	    Source port: 36412
//	    Destination port: 36412
//	    Verification tag: 0x00000000
//	    Checksum: 0x1e66827e
//
//	INIT chunk (Outbound streams: 3, inbound streams: 10)
//	    Chunk type: INIT (1)
//	    Chunk flags: 0x00
//	    Chunk length: 20
//	    Initiate tag: 0xe153413d
//	    Advertised receiver window credit (a_rwnd): 48000
//	    Number of outbound streams: 3
//	    Number of inbound streams: 10
//	    Initial TSN: 3780329789
//
//	0000   8e 3c 8e 3c 00 00 00 00 1e 66 82 7e 01 00 00 14   .<.<.....f.~....
//	0010   e1 53 41 3d 00 00 bb 80 00 03 00 0a e1 53 41 3d   .SA=.........SA=
var sctpTestPacketInit = []byte{
	0x8e, 0x3c, 0x8e, 0x3c, 0x00, 0x00, 0x00, 0x00, 0x1e, 0x66, 0x82, 0x7e, 0x01, 0x00, 0x00, 0x14, // .<.<....f~....
	0xe1, 0x53, 0x41, 0x3d, 0x00, 0x00, 0xbb, 0x80, 0x00, 0x03, 0x00, 0x0a, 0xe1, 0x53, 0x41, 0x3d, // .SA=.......SA=
}

// Packet with an INIT_ACK chunk (SCTPInit):
//
//	Stream Control Transmission Protocol, Src Port: 36412 (36412), Dst Port: 36412 (36412)
//	    Source port: 36412
//	    Destination port: 36412
//	    Verification tag: 0xe153413d
//	    Checksum: 0x48acdf1b
//
//	INIT_ACK chunk (Outbound streams: 2, inbound streams: 2)
//	    Chunk type: INIT_ACK (2)
//	    Chunk flags: 0x00
//	    Chunk length: 452
//	    Initiate tag: 0x03fe3c18
//	    Advertised receiver window credit (a_rwnd): 10000
//	    Number of outbound streams: 2
//	    Number of inbound streams: 2
//	    Initial TSN: 66993176
//	    State cookie parameter (Cookie length: 428 bytes)
//	        Parameter type: State cookie (0x0007)
//	        Parameter length: 432
//	        State cookie […]: 3d4153e180bb0000020000003d4153e1000000003c8e000001000000040000001900350a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//
//	0000   8e 3c 8e 3c e1 53 41 3d 48 ac df 1b 02 00 01 c4   .<.<.SA=H.......
//	0010   03 fe 3c 18 00 00 27 10 00 02 00 02 03 fe 3c 18   ..<...'.......<.
//	0020   00 07 01 b0 3d 41 53 e1 80 bb 00 00 02 00 00 00   ....=AS.........
//	0030   3d 41 53 e1 00 00 00 00 3c 8e 00 00 01 00 00 00   =AS.....<.......
//	0040   04 00 00 00 19 00 35 0a 00 00 00 00 00 00 00 00   ......5.........
//	0050   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//	0060   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//	0070   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//	0080   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//	0090   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//	00a0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//	00b0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//	00c0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//	00d0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//	00e0   00 00 00 00 00 00 00 00 00 00 00 00 18 3c fe 03   .............<..
//	00f0   10 27 00 00 02 00 00 00 18 3c fe 03 3c 8e 00 00   .'.......<..<...
//	0100   01 00 00 00 04 00 00 00 70 00 2b 0a 00 00 00 00   ........p.+.....
//	0110   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//	0120   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//	0130   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//	0140   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//	0150   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//	0160   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//	0170   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//	0180   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//	0190   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//	01a0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//	01b0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//	01c0   00 00 00 00 00 00 00 00 40 b1 37 54 b0 c8 37 54   ........@.7T..7T
var sctpTestPacketInitAck = []byte{
	0x8e, 0x3c, 0x8e, 0x3c, 0xe1, 0x53, 0x41, 0x3d, 0x48, 0xac, 0xdf, 0x1b, 0x02, 0x00, 0x01, 0xc4,
	0x03, 0xfe, 0x3c, 0x18, 0x00, 0x00, 0x27, 0x10, 0x00, 0x02, 0x00, 0x02, 0x03, 0xfe, 0x3c, 0x18,
	0x00, 0x07, 0x01, 0xb0, 0x3d, 0x41, 0x53, 0xe1, 0x80, 0xbb, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
	0x3d, 0x41, 0x53, 0xe1, 0x00, 0x00, 0x00, 0x00, 0x3c, 0x8e, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x04, 0x00, 0x00, 0x00, 0x19, 0x00, 0x35, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x3c, 0xfe, 0x03,
	0x10, 0x27, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x18, 0x3c, 0xfe, 0x03, 0x3c, 0x8e, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x70, 0x00, 0x2b, 0x0a, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0xb1, 0x37, 0x54, 0xb0, 0xc8, 0x37, 0x54,
}

// Packet with a COOKIE_ECHO chunk (SCTPCookieEcho):
//
//	Stream Control Transmission Protocol, Src Port: 36412 (36412), Dst Port: 36412 (36412)
//	    Source port: 36412
//	    Destination port: 36412
//	    Verification tag: 0x03fe3c18
//	    Checksum: 0xf63c2f25
//
//	COOKIE_ECHO chunk (Cookie length: 428 bytes)
//	    Chunk type: COOKIE_ECHO (10)
//	    Chunk flags: 0x00
//	    Chunk length: 432
//	    Cookie […]: 3d4153e180bb0000020000003d4153e1000000003c8e000001000000040000001900350a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//
//	0000   8e 3c 8e 3c 03 fe 3c 18 f6 3c 2f 25 0a 00 01 b0   .<.<..<..</%....
//	0010   3d 41 53 e1 80 bb 00 00 02 00 00 00 3d 41 53 e1   =AS.........=AS.
//	0020   00 00 00 00 3c 8e 00 00 01 00 00 00 04 00 00 00   ....<...........
//	0030   19 00 35 0a 00 00 00 00 00 00 00 00 00 00 00 00   ..5.............
//	0040   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//	0050   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//	0060   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//	0070   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//	0080   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//	0090   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//	00a0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//	00b0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//	00c0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//	00d0   00 00 00 00 00 00 00 00 18 3c fe 03 10 27 00 00   .........<...'..
//	00e0   02 00 00 00 18 3c fe 03 3c 8e 00 00 01 00 00 00   .....<..<.......
//	00f0   04 00 00 00 70 00 2b 0a 00 00 00 00 00 00 00 00   ....p.+.........
//	0100   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//	0110   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//	0120   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//	0130   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//	0140   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//	0150   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//	0160   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//	0170   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//	0180   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//	0190   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//	01a0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
//	01b0   00 00 00 00 40 b1 37 54 b0 c8 37 54               ....@.7T..7T
var sctpTestPacketCookieEcho = []byte{
	0x8e, 0x3c, 0x8e, 0x3c, 0x03, 0xfe, 0x3c, 0x18, 0xf6, 0x3c, 0x2f, 0x25, 0x0a, 0x00, 0x01, 0xb0,
	0x3d, 0x41, 0x53, 0xe1, 0x80, 0xbb, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x3d, 0x41, 0x53, 0xe1,
	0x00, 0x00, 0x00, 0x00, 0x3c, 0x8e, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
	0x19, 0x00, 0x35, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x3c, 0xfe, 0x03, 0x10, 0x27, 0x00, 0x00,
	0x02, 0x00, 0x00, 0x00, 0x18, 0x3c, 0xfe, 0x03, 0x3c, 0x8e, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x04, 0x00, 0x00, 0x00, 0x70, 0x00, 0x2b, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x40, 0xb1, 0x37, 0x54, 0xb0, 0xc8, 0x37, 0x54,
}

// Packet with a COOKIE_ACK chunk (SCTPCookieEcho):
//
//	Stream Control Transmission Protocol, Src Port: 36412 (36412), Dst Port: 36412 (36412)
//	    Source port: 36412
//	    Destination port: 36412
//	    Verification tag: 0xe153413d
//	    Checksum: 0x24057544
//
//	COOKIE_ACK chunk
//	    Chunk type: COOKIE_ACK (11)
//	    Chunk flags: 0x00
//	    Chunk length: 4
//
//	0000   8e 3c 8e 3c e1 53 41 3d 24 05 75 44 0b 00 00 04   .<.<.SA=$.uD....
var sctpTestPacketCookieAck = []byte{
	0x8e, 0x3c, 0x8e, 0x3c, 0xe1, 0x53, 0x41, 0x3d, 0x24, 0x05, 0x75, 0x44, 0x0b, 0x00, 0x00, 0x04,
}

// Packet with a DATA chunk (SCTPData):
//
//	Stream Control Transmission Protocol, Src Port: 36412 (36412), Dst Port: 36412 (36412)
//	    Source port: 36412
//	    Destination port: 36412
//	    Verification tag: 0x03fe3c18
//	    Checksum: 0x9a730e6f
//
//	DATA chunk (ordered, complete segment, TSN: 0, SID: 0, SSN: 0, PPID: 18, payload length: 44 bytes)
//	    Chunk type: DATA (0)
//	    Chunk flags: 0x03
//	    Chunk length: 60
//	    Transmission sequence number (relative): 0
//	    Transmission sequence number (absolute): 3780329789
//	    Stream identifier: 0x0002
//	    Stream sequence number: 1
//	    Payload protocol identifier: S1 Application Protocol (S1AP) (18)
//
//	0000   8e 3c 8e 3c 03 fe 3c 18 94 b8 d8 da 00 03 00 3c   .<.<..<........<
//	0010   e1 53 41 3d 00 00 00 00 00 00 00 12               .SA=........
//
//	S1 Application Protocol
//	  S1AP-PDU: initiatingMessage (0)
//	    initiatingMessage
//
//	0000   00 11 00 28 00 00 04 00 3b 00 08 00 00 f2 10 00   ...(....;.......
//	0010   13 64 e0 00 3c 40 05 01 00 43 57 53 00 40 00 07   .d..<@...CWS.@..
//	0020   00 0c 4c 80 00 f2 10 00 89 40 01 40               ..L......@.@
var sctpTestPacketData = []byte{
	0x8e, 0x3c, 0x8e, 0x3c, 0x03, 0xfe, 0x3c, 0x18, 0x9a, 0x73, 0x0e, 0x6f, 0x00, 0x03, 0x00, 0x3c,
	0xe1, 0x53, 0x41, 0x3d, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x12, 0x00, 0x11, 0x00, 0x28,
	0x00, 0x00, 0x04, 0x00, 0x3b, 0x00, 0x08, 0x00, 0x00, 0xf2, 0x10, 0x00, 0x13, 0x64, 0xe0, 0x00,
	0x3c, 0x40, 0x05, 0x01, 0x00, 0x43, 0x57, 0x53, 0x00, 0x40, 0x00, 0x07, 0x00, 0x0c, 0x4c, 0x80,
	0x00, 0xf2, 0x10, 0x00, 0x89, 0x40, 0x01, 0x40,
}

// Packet with a SACK chunk (SCTPSack):
//
//	Stream Control Transmission Protocol, Src Port: 36412 (36412), Dst Port: 36412 (36412)
//	    Source port: 36412
//	    Destination port: 36412
//	    Verification tag: 0xe153413d
//	    Checksum: 0xb28cf856
//
//	SACK chunk (Cumulative TSN: 3780329789, a_rwnd: 10000, gaps: 0, duplicate TSNs: 0)
//	    Chunk type: SACK (3)
//	    Chunk flags: 0x00
//	        .... ...0 = Nonce sum: 0
//	    Chunk length: 16
//	    Cumulative TSN ACK (relative): 0
//	    Cumulative TSN ACK (absolute): 3780329789
//	    Advertised receiver window credit (a_rwnd): 10000
//	    Number of gap acknowledgement blocks: 0
//	    Number of duplicated TSNs: 0
//
//	0000   8e 3c 8e 3c e1 53 41 3d b2 8c f8 56 03 00 00 10   .<.<.SA=...V....
//	0010   e1 53 41 3d 00 00 27 10 00 00 00 00               .SA=..'.....
var sctpTestPacketSack = []byte{
	0x8e, 0x3c, 0x8e, 0x3c, 0xe1, 0x53, 0x41, 0x3d, 0xb2, 0x8c, 0xf8, 0x56, 0x03, 0x00, 0x00, 0x10,
	0xe1, 0x53, 0x41, 0x3d, 0x00, 0x00, 0x27, 0x10, 0x00, 0x00, 0x00, 0x00,
}

// Packet with a HEARTBEAT chunk (SCTPHeartbeat):
//
//	Stream Control Transmission Protocol, Src Port: 36412 (36412), Dst Port: 36412 (36412)
//	    Source port: 36412
//	    Destination port: 36412
//	    Verification tag: 0xe153413d
//	    Checksum: 0x439fe16b
//
//	HEARTBEAT chunk (Information: 16 bytes)
//	    Chunk type: HEARTBEAT (4)
//	    Chunk flags: 0x00
//	    Chunk length: 20
//	    Heartbeat info parameter (Information: 12 bytes)
//	        Parameter type: Heartbeat info (0x0001)
//	        Parameter length: 16
//	        Heartbeat information: 0058afa2000500080a350019
//
//	0000   8e 3c 8e 3c e1 53 41 3d 43 9f e1 6b 04 00 00 14   .<.<.SA=C..k....
//	0010   00 01 00 10 00 58 af a2 00 05 00 08 0a 35 00 19   .....X.......5..
var sctpTestPacketHeartbeat = []byte{
	0x8e, 0x3c, 0x8e, 0x3c, 0xe1, 0x53, 0x41, 0x3d, 0x43, 0x9f, 0xe1, 0x6b, 0x04, 0x00, 0x00, 0x14,
	0x00, 0x01, 0x00, 0x10, 0x00, 0x58, 0xaf, 0xa2, 0x00, 0x05, 0x00, 0x08, 0x0a, 0x35, 0x00, 0x19,
}

// Packet with a HEARTBEAT_ACK chunk (SCTPHeartbeat):
//
//	Stream Control Transmission Protocol, Src Port: 36412 (36412), Dst Port: 36412 (36412)
//	    Source port: 36412
//	    Destination port: 36412
//	    Verification tag: 0x03fe3c18
//	    Checksum: 0x46b77608
//
//	HEARTBEAT_ACK chunk (Information: 16 bytes)
//	    Chunk type: HEARTBEAT_ACK (5)
//	    Chunk flags: 0x00
//	    Chunk length: 20
//	    Heartbeat info parameter (Information: 12 bytes)
//	        Parameter type: Heartbeat info (0x0001)
//	        Parameter length: 16
//	        Heartbeat information: 0058afa2000500080a350019
//
//	0000   8e 3c 8e 3c 03 fe 3c 18 46 b7 76 08 05 00 00 14   .<.<..<.F.v.....
//	0010   00 01 00 10 00 58 af a2 00 05 00 08 0a 35 00 19   .....X.......5..
var sctpTestPacketHeartbeatAck = []byte{
	0x8e, 0x3c, 0x8e, 0x3c, 0x03, 0xfe, 0x3c, 0x18, 0x46, 0xb7, 0x76, 0x08, 0x05, 0x00, 0x00, 0x14,
	0x00, 0x01, 0x00, 0x10, 0x00, 0x58, 0xaf, 0xa2, 0x00, 0x05, 0x00, 0x08, 0x0a, 0x35, 0x00, 0x19,
}

// Packet with SHUTDOWN (SCTPShutdown), SHUTDOWN_ACK (SCTPShutdownAck), and
// SHUTDOWN_COMPLETE (SCTPEmptyLayer) chunks:
//
//	Stream Control Transmission Protocol, Src Port: 36412 (36412), Dst Port: 36412 (36412)
//	    Source port: 36412
//	    Destination port: 36412
//	    Verification tag: 0xe153413d
//	    Checksum: 0xb28cf856
//
//	SHUTDOWN chunk (Cumulative TSN: 2241376549)
//	    Chunk type: SHUTDOWN (7)
//	    Chunk flags: 0x00
//	    Chunk length: 8
//	    Cumulative TSN ACK: 2241376549
//
//	SHUTDOWN_ACK chunk
//	    Chunk type: SHUTDOWN_ACK (8)
//	    Chunk flags: 0x00
//	    Chunk length: 4
//
//	SHUTDOWN_COMPLETE chunk
//	    Chunk type: SHUTDOWN_COMPLETE (14)
//	    Chunk flags: 0x00
//	    Chunk length: 4
//
//	0000   8e 3c 8e 3c e1 53 41 3d d1 e2 36 c5 07 00 00 08   .<.<.SA=...V....
//	0010   85 98 b1 25 08 00 00 04 0e 00 00 04               ...%........
var sctpTestPacketShutdowns = []byte{
	0x8e, 0x3c, 0x8e, 0x3c, 0xe1, 0x53, 0x41, 0x3d, 0xd1, 0xe2, 0x36, 0xc5, 0x07, 0x00, 0x00, 0x08,
	0x85, 0x98, 0xb1, 0x25, 0x08, 0x00, 0x00, 0x04, 0x0e, 0x00, 0x00, 0x04,
}

// Packet with bundled SACK (SCTPSack) and DATA (SCTPData) chunks:
//
//	Stream Control Transmission Protocol, Src Port: 36412 (36412), Dst Port: 36412 (36412)
//	    Source port: 36412
//	    Destination port: 36412
//	    Verification tag: 0x03fe3c18
//	    Checksum: 0xd3041fa4
//
//	SACK chunk (Cumulative TSN: 66993177, a_rwnd: 48000, gaps: 0, duplicate TSNs: 0)
//	    Chunk type: SACK (3)
//	    Chunk flags: 0x00
//	    Chunk length: 16
//	    Cumulative TSN ACK (relative): 1
//	    Cumulative TSN ACK (absolute): 66993177
//	    Advertised receiver window credit (a_rwnd): 48000
//	    Number of gap acknowledgement blocks: 0
//	    Number of duplicated TSNs: 0
//
//	DATA chunk (ordered, complete segment, TSN: 1, SID: 0, SSN: 1, PPID: 18, payload length: 7 bytes)
//	    Chunk type: DATA (0)
//	    Chunk flags: 0x03
//	    Chunk length: 23
//	    Transmission sequence number (relative): 1
//	    Transmission sequence number (absolute): 3780329790
//	    Stream identifier: 0x0000
//	    Stream sequence number: 1
//	    Payload protocol identifier: S1 Application Protocol (S1AP) (18)
//	    Chunk padding: 00
//
//	0000   8e 3c 8e 3c 03 fe 3c 18 d3 04 1f a4 03 00 00 10   .<.<..<.........
//	0010   03 fe 3c 19 00 00 bb 80 00 00 00 00 00 03 00 17   ..<.............
//	0020   e1 53 41 3e 00 00 00 01 00 00 00 12               .SA>........
//
//	S1 Application Protocol
//	  S1AP-PDU: successfulOutcome (1)
//	    successfulOutcome
//	      procedureCode: id-MMEConfigurationUpdate (30)
//	      criticality: reject (0)
//	      value
//	        MMEConfigurationUpdateAcknowledge
//	          protocolIEs: 0 items
//
//	0000   20 1e 00 03 00 00 00                               ......
//
//	Chunk padding
//
//	0000   00                                                 .
var sctpTestBundledPacket = []byte{
	0x8e, 0x3c, 0x8e, 0x3c, 0x03, 0xfe, 0x3c, 0x18, 0xd3, 0x04, 0x1f, 0xa4, 0x03, 0x00, 0x00, 0x10,
	0x03, 0xfe, 0x3c, 0x19, 0x00, 0x00, 0xbb, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x17,
	0xe1, 0x53, 0x41, 0x3e, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x12, 0x20, 0x1e, 0x00, 0x03,
	0x00, 0x00, 0x00, 0x00,
}

// Packet with multiple chunks of unknown types (SCTPUnknownChunkType or error):
//
//	Stream Control Transmission Protocol, Src Port: 36412 (36412), Dst Port: 36412 (36412)
//	    Source port: 36412
//	    Destination port: 36412
//	    Verification tag: 0xe153413d
//	    Checksum: 0xc515803a
//
//	Unknown chunk (Type: 255, Length: 4)
//	    Chunk type: 255 (0xff)
//	    Chunk flags: 0x00
//	    Chunk length: 4
//
//	Unknown chunk (Type: 255, Length: 16)
//	    Chunk type: 254 (0xfe)
//	    Chunk flags: 0x00
//	    Chunk length: 16
//	    Chunk data: 0405060708090a0b0c0d0e0f
//
//	0000   8e 3c 8e 3c e1 53 41 3d c5 15 80 3a ff 00 00 04   .<.<.SA=..6.....
//	0010   ff 00 00 10 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f   ................
//
// Chunks are either SCTPUnknownChunkType or gopacket.LayerTypeDecodeFailure
// based on whether the specific chunk-type was registered with
// SCTPChunkTypeMetadata.
var sctpTestPacketUnknown = []byte{
	0x8e, 0x3c, 0x8e, 0x3c, 0xe1, 0x53, 0x41, 0x3d, 0xc5, 0x15, 0x80, 0x3a, 0xff, 0x00, 0x00, 0x04,
	0xfe, 0x00, 0x00, 0x10, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
}

// This test progressively builds an SCTP packet to test truncation detection.
//
// The complete final packet structure is:
//
//	|-- SCTP Header (12 bytes) --|------------- DATA Chunk (17 bytes) -------------|
//	|----+----+--------+---------|--+--+----+--------+----+----+--------+-------+--|
//	|Src |Dst |VTag    |Checksum |T |Fl|Len |TSN     |SID |SSN |PPID    |Payload|Pd|
//	|----|----|--------|---------|--|--|----|--------|----|----|--------|-------|--|
//	|8e3c|8e3c|03fe3c18|9a730e6f |00|03|0013|e153413d|0002|0001|00000012|010203 |00|
//
// Test progression (each step tests truncation detection):
//  1. SCTP Header only (12 bytes) → Valid empty packet
//  2. + ChunkType (1 byte) → Truncated
//  3. + Flags+Length (3 bytes) → Truncated
//  4. + TSN+SID+SSN+PPID (13 bytes) → Truncated
//  5. + User Data (3 bytes) → Truncated
//  6. + Padding (1 byte) → Complete valid packet
func TestDecodingTruncatedSCTPChunks(t *testing.T) {
	// First, let's test decoding an SCTP packet with no chunks at all. An SCTP
	// packet may be "blank" containing no chunks; it does not constitute an error.
	//
	// SCTP DATA chunk header: 0/16 bytes.
	// SCTP DATA user-data: 0/3 bytes.
	// SCTP chunk padding: 0/1 bytes.
	packetData := []byte{
		0x8e, 0x3c, 0x8e, 0x3c, 0x03, 0xfe, 0x3c, 0x18, 0x9a, 0x73, 0x0e, 0x6f,
	}
	p := gopacket.NewPacket(packetData, LayerTypeSCTP, gopacket.NoCopy)
	if p.ErrorLayer() != nil {
		t.Errorf("NewPacket(blank SCTP packet) = %v; want nil", p.ErrorLayer())
	}
	if p.Metadata().Truncated {
		t.Errorf("NewPacket(blank SCTP packet) marked as truncated, but it should not be")
	}

	// Now, let's append only the ChunkType field.
	//
	// SCTP DATA chunk header: 1/16 bytes.
	// SCTP DATA user-data: 0/3 bytes.
	// SCTP chunk padding: 0/1 bytes.
	packetData = append(packetData,
		0x00, // ChunkType = DATA
	)
	testTruncatedPacketOnSCTP(t, packetData, "chunk-type only")

	// Now, let's append only the Flags and Length fields.
	//
	// SCTP DATA chunk header: 3/16 bytes.
	// SCTP DATA user-data: 0/3 bytes.
	// SCTP chunk padding: 0/1 bytes.
	packetData = append(packetData,
		0x03,       // Flags = Ordered, Begin, End
		0x00, 0x13, // Length = 19
	)
	testTruncatedPacketOnSCTP(t, packetData, "incomplete chunk")

	// Now, let's append the rest of the DATA header.
	//
	// SCTP DATA chunk header: 16/16 bytes.
	// SCTP DATA user-data: 0/3 bytes.
	// SCTP chunk padding: 0/1 bytes.
	packetData = append(packetData,
		0xe1, 0x53, 0x41, 0x3d, // TSN = 3780329789
		0x00, 0x02, // StreamId = 2
		0x00, 0x01, // StreamSequence = 1
		0x00, 0x00, 0x00, 0x12, // PayloadProtocol = S1AP
	)
	testTruncatedPacketOnSCTP(t, packetData, "without payload")

	// Now, let's append the user-data of the DATA chunk.
	//
	// SCTP DATA chunk header: 16/16 bytes.
	// SCTP DATA user-data: 3/3 bytes.
	// SCTP chunk padding: 0/1 bytes.
	packetData = append(packetData, 0x01, 0x02, 0x03)
	testTruncatedPacketOnSCTP(t, packetData, "without padding")

	// Finally, let's complete the DATA chunk by appending the padding byte.
	//
	// SCTP DATA chunk header: 16/16 bytes.
	// SCTP DATA user-data: 3/3 bytes.
	// SCTP chunk padding: 1/1 bytes.
	packetData = append(packetData, 0x00)
	p = gopacket.NewPacket(packetData, LayerTypeSCTP, gopacket.NoCopy)
	if p.ErrorLayer() != nil {
		t.Errorf("NewPacket(full SCTP packet) = %v; want nil", p.ErrorLayer())
	}
	if p.Metadata().Truncated {
		t.Errorf("NewPacket(full SCTP packet) marked as truncated, but it should not be")
	}
}

func testTruncatedPacketOnSCTP(t *testing.T, packetData []byte, description string) {
	t.Helper()

	p := gopacket.NewPacket(packetData, LayerTypeSCTP, gopacket.NoCopy)
	t.Logf("NewPacket(%v).ErrorLayer() = %v", description, p.ErrorLayer())
	// We know SCTP truncated packets are not decoded successfully.
	if p.ErrorLayer() == nil {
		t.Errorf("NewPacket(%v) did not set an error layer", description)
	}
	// When the given data is truncated, the returned packet should be marked as
	// such.
	if !p.Metadata().Truncated {
		t.Errorf("NewPacket(%v) did not mark the packet as truncated", description)
	}
}
