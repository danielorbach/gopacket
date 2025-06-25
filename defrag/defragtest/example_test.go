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
// payloads into several packets for testing defragmentation packages.
//
// The example shows how to fragment a UDP packet that exceeds the MTU, creating
// multiple IPv4 fragments with proper fragment offsets and flags.
//
// The generated packets are accessible by reading packet data from the
// [gopacket.PacketDataSource] returned by [defragtest.DataSource]. It takes a
// payload to split into parts and a [defragtest.Template] to render each part as
// the appropriate layers.
//
// The package also exposes several options to customize how the payload is
// fragmented. See [defragtest.Options] and its With* functions for more details.
func Example() {
	// Simulate a large UDP packet payload that will be fragmented. In a real
	// scenario, this could be any byte slice.
	const largeUDPPayload = "This is a large payload that exceeds the MTU and must be fragmented at the IP layer"

	// The package exposes TemplateFunc to easily use arbitrary functions as
	// Templates. We've created a template function that demonstrates proper IPv4
	// fragmentation.
	template := defragtest.TemplateFunc(RenderIPv4Fragment)
	// The DataSource function returns a synthetic packet data source that can be
	// used to generate packets containing each fragment.
	packetDataSource, err := defragtest.DataSource(template, []byte(largeUDPPayload),
		// Callers must set either the number of fragments (using WithFragments) or the
		// maximum size of each fragment (using WithMaxFragmentSize). The two options are
		// mutually exclusive, so DataSource will fail if both are present.
		//
		// Here we fragment the payload into 3 pieces to simulate MTU constraints. Each
		// fragment will be ~30 bytes of the original payload.
		defragtest.WithFragments(3),
		// You may set the timestamp as part of the gopacket.CaptureInfo of each packet.
		defragtest.WithCaptureTimestamp(time.Date(2006, 5, 4, 3, 2, 1, 0, time.UTC)),
		// In most production scenarios, fragments don't just appear to standalone,
		// rather as a payload of another protocol that supports fragmentation of its
		// user data. To better mimic those scenarios, the package allows users to
		// specify several layers that carry each fragment.
		defragtest.WithLayers(
			// This is just a typical Ethernet packet.
			&layers.Ethernet{
				SrcMAC:       net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
				DstMAC:       net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
				EthernetType: layers.EthernetTypeIPv4,
				Length:       0, // Don't worry about lengths in the base layers, gopacket fixes those automatically.
			},
		),
		// Sometimes packets arrive in a different order than expected. This package
		// comes with several orders to thoroughly test defragmentation mechanisms. Note
		// that we chose an API that prevents users from providing their own order
		// functions.
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
	// -- FULL PACKET DATA (62 bytes) ------------------------------------
	// 00000000  11 22 33 44 55 66 aa bb  cc dd ee ff 08 00 45 00  |."3DUf........E.|
	// 00000010  00 30 00 07 20 03 06 11  80 b1 0a 00 00 01 0a 00  |.0.. ...........|
	// 00000020  00 02 20 65 78 63 65 65  64 73 20 74 68 65 20 4d  |.. exceeds the M|
	// 00000030  54 55 20 61 6e 64 20 6d  75 73 74 20 62 65        |TU and must be|
	// --- Layer 1 ---
	// Ethernet	{Contents=[..14..] Payload=[..48..] SrcMAC=aa:bb:cc:dd:ee:ff DstMAC=11:22:33:44:55:66 EthernetType=IPv4 Length=0}
	// 00000000  11 22 33 44 55 66 aa bb  cc dd ee ff 08 00        |."3DUf........|
	// --- Layer 2 ---
	// IPv4	{Contents=[..20..] Payload=[..28..] Version=4 IHL=5 TOS=0 Length=48 Id=7 Flags=MF FragOffset=3 TTL=6 Protocol=UDP Checksum=32945 SrcIP=10.0.0.1 DstIP=10.0.0.2 Options=[] Padding=[]}
	// 00000000  45 00 00 30 00 07 20 03  06 11 80 b1 0a 00 00 01  |E..0.. .........|
	// 00000010  0a 00 00 02                                       |....|
	// --- Layer 3 ---
	// Fragment	28 byte(s)
	// 00000000  20 65 78 63 65 65 64 73  20 74 68 65 20 4d 54 55  | exceeds the MTU|
	// 00000010  20 61 6e 64 20 6d 75 73  74 20 62 65              | and must be|
	//
	// Captured packet at 2006-05-04 03:02:01 +0000 UTC
	// -- FULL PACKET DATA (62 bytes) ------------------------------------
	// 00000000  11 22 33 44 55 66 aa bb  cc dd ee ff 08 00 45 00  |."3DUf........E.|
	// 00000010  00 30 00 07 20 00 06 11  80 b4 0a 00 00 01 0a 00  |.0.. ...........|
	// 00000020  00 02 54 68 69 73 20 69  73 20 61 20 6c 61 72 67  |..This is a larg|
	// 00000030  65 20 70 61 79 6c 6f 61  64 20 74 68 61 74        |e payload that|
	// --- Layer 1 ---
	// Ethernet	{Contents=[..14..] Payload=[..48..] SrcMAC=aa:bb:cc:dd:ee:ff DstMAC=11:22:33:44:55:66 EthernetType=IPv4 Length=0}
	// 00000000  11 22 33 44 55 66 aa bb  cc dd ee ff 08 00        |."3DUf........|
	// --- Layer 2 ---
	// IPv4	{Contents=[..20..] Payload=[..28..] Version=4 IHL=5 TOS=0 Length=48 Id=7 Flags=MF FragOffset=0 TTL=6 Protocol=UDP Checksum=32948 SrcIP=10.0.0.1 DstIP=10.0.0.2 Options=[] Padding=[]}
	// 00000000  45 00 00 30 00 07 20 00  06 11 80 b4 0a 00 00 01  |E..0.. .........|
	// 00000010  0a 00 00 02                                       |....|
	// --- Layer 3 ---
	// Fragment	28 byte(s)
	// 00000000  54 68 69 73 20 69 73 20  61 20 6c 61 72 67 65 20  |This is a large |
	// 00000010  70 61 79 6c 6f 61 64 20  74 68 61 74              |payload that|
	//
	// Captured packet at 2006-05-04 03:02:01 +0000 UTC
	// -- FULL PACKET DATA (61 bytes) ------------------------------------
	// 00000000  11 22 33 44 55 66 aa bb  cc dd ee ff 08 00 45 00  |."3DUf........E.|
	// 00000010  00 2f 00 07 00 07 06 11  a0 ae 0a 00 00 01 0a 00  |./..............|
	// 00000020  00 02 20 66 72 61 67 6d  65 6e 74 65 64 20 61 74  |.. fragmented at|
	// 00000030  20 74 68 65 20 49 50 20  6c 61 79 65 72           | the IP layer|
	// --- Layer 1 ---
	// Ethernet	{Contents=[..14..] Payload=[..47..] SrcMAC=aa:bb:cc:dd:ee:ff DstMAC=11:22:33:44:55:66 EthernetType=IPv4 Length=0}
	// 00000000  11 22 33 44 55 66 aa bb  cc dd ee ff 08 00        |."3DUf........|
	// --- Layer 2 ---
	// IPv4	{Contents=[..20..] Payload=[..27..] Version=4 IHL=5 TOS=0 Length=47 Id=7 Flags= FragOffset=7 TTL=6 Protocol=UDP Checksum=41134 SrcIP=10.0.0.1 DstIP=10.0.0.2 Options=[] Padding=[]}
	// 00000000  45 00 00 2f 00 07 00 07  06 11 a0 ae 0a 00 00 01  |E../............|
	// 00000010  0a 00 00 02                                       |....|
	// --- Layer 3 ---
	// Fragment	27 byte(s)
	// 00000000  20 66 72 61 67 6d 65 6e  74 65 64 20 61 74 20 74  | fragmented at t|
	// 00000010  68 65 20 49 50 20 6c 61  79 65 72                 |he IP layer|
}

// RenderIPv4Fragment demonstrates how to properly handle IPv4 fragmentation. It
// creates an IPv4 layer with the correct fragment offset and flags based on the
// fragment's position in the sequence.
//
// This example shows the pattern for protocol-specific fragmentation:
//   - First fragment (index 0): Contains the original protocol header (this time: UDP)
//     with FragOffset=0 and the More Fragments flag set.
//   - Middle fragments: Have appropriate FragOffset values and MF flag set.
//   - Last fragment (index == total-1): Has FragOffset set but MF flag cleared.
//
// Similar patterns apply to other protocols:
//   - SCTP: Would set BeginFragment and EndFragment flags in the DATA chunk.
//   - IPv6: Would add a Fragment Extension Header with offset and M flag.
//   - Custom protocols: Would include their own fragmentation metadata.
func RenderIPv4Fragment(payload []byte, position, totalFragments, offset, totalBytes int) ([]gopacket.SerializableLayer, error) {
	_ = totalBytes // Unused in this protocol.
	// Create an IPv4 layer with common fields.
	ipv4 := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      6,
		Id:       7,                    // Same ID for all fragments of this packet.
		Protocol: layers.IPProtocolUDP, // Assume we're fragmenting UDP.
		SrcIP:    net.IPv4(10, 0, 0, 1),
		DstIP:    net.IPv4(10, 0, 0, 2),
		Checksum: 0, // Don't worry about checksums in the base layers, gopacket fixes those automatically.
	}

	// Convert byte offset to 8-byte units as required by IPv4.
	//
	// Note that this value is not necessarily accurate because this package does not
	// guarantee that fragments are filled to 8-byte boundaries.
	fragmentOffset := uint16(offset / 8)

	if position == 0 {
		// First fragment: offset 0, more fragments coming.
		ipv4.FragOffset = 0
		ipv4.Flags = layers.IPv4MoreFragments
	} else if position == totalFragments-1 {
		// Last fragment: has offset, no more fragments.
		ipv4.FragOffset = fragmentOffset
		ipv4.Flags = 0
	} else {
		// Middle fragment: has offset, more fragments coming.
		ipv4.FragOffset = fragmentOffset
		ipv4.Flags = layers.IPv4MoreFragments
	}

	// Return both the IPv4 layer and a Fragment layer with the payload This
	// demonstrates how templates can return multiple layers.
	frag := gopacket.Fragment(payload)
	return []gopacket.SerializableLayer{ipv4, &frag}, nil
}
