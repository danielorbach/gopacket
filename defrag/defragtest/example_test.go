package defragtest_test

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/defrag/defragtest"
	"github.com/google/gopacket/layers"
)

// This example demonstrates how to use the defragtest package to fragment
// messages into several packets for testing defragmentation packages.
//
// The entrypoint into this package is its [defragtest.DataSource] function. It
// takes a payload to split into parts and a [defragtest.Template] to render each
// part as the appropriate layer.
//
// The package also exposes several options to customize how the payload is
// fragmented. See [defragtest.Options] and its With* functions for more details.
func Example() {
	// For this example, we use this string, but any slice of bytes will do.
	const message = "Hello, world! I am a large message..."

	// The package exposes TemplateFunc to easily use arbitrary functions as
	// Templates.
	template := defragtest.TemplateFunc(RenderGenericFragment)
	// The DataSource function returns a synthetic packet data source that can be
	// used to generate packets containing each fragment.
	packetDataSource, err := defragtest.DataSource(template, []byte(message),
		// You must set either the number of fragments (using WithFragments) or the
		// maximum size of each fragment (using WithMaxFragmentSize). The two options are
		// mutually exclusive, so DataSource will fail if both are present.
		defragtest.WithFragments(3),
		// You may set the timestamp as part of the gopacket.CaptureInfo of each packet.
		defragtest.WithCaptureTimestamp(time.Date(2006, 5, 4, 3, 2, 1, 0, time.UTC)),
		// In most production scenarios, fragments don't just appear to standalone,
		// rather as a payload of another protocol that supports fragmentation of its
		// user data. To better mimic those scenarios, the package allows users to
		// specify several layers that transport each fragment.
		defragtest.WithLayers(
			// This is just a typical Ethernet packet.
			&layers.Ethernet{
				SrcMAC:       net.HardwareAddr{1, 1, 1, 1, 1, 1},
				DstMAC:       net.HardwareAddr{2, 2, 2, 2, 2, 2},
				EthernetType: layers.EthernetTypeIPv4,
				Length:       0, // Don't worry about lengths in the base layers, gopacket fixes those automatically.
			},
			// This is just a typical IPv4 packet.
			&layers.IPv4{
				Version:    4,
				IHL:        5,
				TTL:        15,
				SrcIP:      net.IPv4(3, 3, 3, 3),
				DstIP:      net.IPv4(4, 4, 4, 4),
				Id:         0xcc,
				FragOffset: 0,
				Flags:      layers.IPv4MoreFragments,
				Checksum:   0, // Don't worry about checksums in the base layers, gopacket fixes those automatically.
			},
		),
		// Sometimes packets arrive in a different order than expected. This package
		// comes with several orders. Note that we chose an API that prevents users from
		// providing their own order functions.
		defragtest.WithOrder(defragtest.ShuffleOrder),
	)
	if err != nil {
		panic(err)
	}

	// Now that we have a packet data source at hand, let's consume it and print its
	// packets.
	packetSource := gopacket.NewPacketSource(packetDataSource, layers.LayerTypeEthernet)
	for p := range packetSource.Packets() {
		fmt.Printf("Captured packet at %s\n", p.Metadata().CaptureInfo.Timestamp)
		fmt.Println(p.Dump())
	}

	// Output:
	// Captured packet at 2006-05-04 03:02:01 +0000 UTC
	// -- FULL PACKET DATA (60 bytes) ------------------------------------
	// 00000000  02 02 02 02 02 02 01 01  01 01 01 01 08 00 45 00  |..............E.|
	// 00000010  00 21 00 cc 20 00 0f 00  7d 04 03 03 03 03 04 04  |.!.. ...}.......|
	// 00000020  04 04 20 49 20 61 6d 20  61 20 6c 61 72 67 65 00  |.. I am a large.|
	// 00000030  00 00 00 00 00 00 00 00  00 00 00 00              |............|
	// --- Layer 1 ---
	// Ethernet	{Contents=[..14..] Payload=[..46..] SrcMAC=01:01:01:01:01:01 DstMAC=02:02:02:02:02:02 EthernetType=IPv4 Length=0}
	// 00000000  02 02 02 02 02 02 01 01  01 01 01 01 08 00        |..............|
	// --- Layer 2 ---
	// IPv4	{Contents=[..20..] Payload=[..13..] Version=4 IHL=5 TOS=0 Length=33 Id=204 Flags=MF FragOffset=0 TTL=15 Protocol=IPv6HopByHop Checksum=32004 SrcIP=3.3.3.3 DstIP=4.4.4.4 Options=[] Padding=[]}
	// 00000000  45 00 00 21 00 cc 20 00  0f 00 7d 04 03 03 03 03  |E..!.. ...}.....|
	// 00000010  04 04 04 04                                       |....|
	// --- Layer 3 ---
	// Fragment	13 byte(s)
	// 00000000  20 49 20 61 6d 20 61 20  6c 61 72 67 65           | I am a large|
	//
	// Captured packet at 2006-05-04 03:02:01 +0000 UTC
	// -- FULL PACKET DATA (60 bytes) ------------------------------------
	// 00000000  02 02 02 02 02 02 01 01  01 01 01 01 08 00 45 00  |..............E.|
	// 00000010  00 21 00 cc 20 00 0f 00  7d 04 03 03 03 03 04 04  |.!.. ...}.......|
	// 00000020  04 04 48 65 6c 6c 6f 2c  20 77 6f 72 6c 64 21 00  |..Hello, world!.|
	// 00000030  00 00 00 00 00 00 00 00  00 00 00 00              |............|
	// --- Layer 1 ---
	// Ethernet	{Contents=[..14..] Payload=[..46..] SrcMAC=01:01:01:01:01:01 DstMAC=02:02:02:02:02:02 EthernetType=IPv4 Length=0}
	// 00000000  02 02 02 02 02 02 01 01  01 01 01 01 08 00        |..............|
	// --- Layer 2 ---
	// IPv4	{Contents=[..20..] Payload=[..13..] Version=4 IHL=5 TOS=0 Length=33 Id=204 Flags=MF FragOffset=0 TTL=15 Protocol=IPv6HopByHop Checksum=32004 SrcIP=3.3.3.3 DstIP=4.4.4.4 Options=[] Padding=[]}
	// 00000000  45 00 00 21 00 cc 20 00  0f 00 7d 04 03 03 03 03  |E..!.. ...}.....|
	// 00000010  04 04 04 04                                       |....|
	// --- Layer 3 ---
	// Fragment	13 byte(s)
	// 00000000  48 65 6c 6c 6f 2c 20 77  6f 72 6c 64 21           |Hello, world!|
	//
	// Captured packet at 2006-05-04 03:02:01 +0000 UTC
	// -- FULL PACKET DATA (60 bytes) ------------------------------------
	// 00000000  02 02 02 02 02 02 01 01  01 01 01 01 08 00 45 00  |..............E.|
	// 00000010  00 1f 00 cc 20 00 0f 00  7d 06 03 03 03 03 04 04  |.... ...}.......|
	// 00000020  04 04 20 6d 65 73 73 61  67 65 2e 2e 2e 00 00 00  |.. message......|
	// 00000030  00 00 00 00 00 00 00 00  00 00 00 00              |............|
	// --- Layer 1 ---
	// Ethernet	{Contents=[..14..] Payload=[..46..] SrcMAC=01:01:01:01:01:01 DstMAC=02:02:02:02:02:02 EthernetType=IPv4 Length=0}
	// 00000000  02 02 02 02 02 02 01 01  01 01 01 01 08 00        |..............|
	// --- Layer 2 ---
	// IPv4	{Contents=[..20..] Payload=[..11..] Version=4 IHL=5 TOS=0 Length=31 Id=204 Flags=MF FragOffset=0 TTL=15 Protocol=IPv6HopByHop Checksum=32006 SrcIP=3.3.3.3 DstIP=4.4.4.4 Options=[] Padding=[]}
	// 00000000  45 00 00 1f 00 cc 20 00  0f 00 7d 06 03 03 03 03  |E..... ...}.....|
	// 00000010  04 04 04 04                                       |....|
	// --- Layer 3 ---
	// Fragment	11 byte(s)
	// 00000000  20 6d 65 73 73 61 67 65  2e 2e 2e                 | message...|
}

// RenderGenericFragment is an example implementation of a simple template
// function that wraps payloads in a generic gopacket.Fragment layer.
//
// In real-world implementations, you would typically:
//   - Use index to set fragment-specific fields (e.g. fragment offset).
//   - Use total to determine if this is the last fragment (e.g. to clear a "more fragments" flag).
//   - Create protocol-specific layers instead of generic Fragment.
//   - Handle fragmentation headers or other protocol requirements.
//
// For example, an SCTP template might set BeginFragment and
// EndFragment flags based on whether this is the first or last fragment in the
// sequence.
func RenderGenericFragment(payload []byte, index, total int) (gopacket.SerializableLayer, error) {
	// In a real implementation, these would be used to configure the fragment.
	//
	// For example, the opening fragment is denoted by (index == 0) and the closing
	// fragment is denoted by (index == total-1).
	_ = index // Fragment position in sequence (0-based).
	_ = total // Total number of fragments.

	frag := gopacket.Fragment(payload)
	return &frag, nil
}
