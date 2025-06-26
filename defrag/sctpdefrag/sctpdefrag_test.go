package sctpdefrag_test

import (
	"bytes"
	_ "embed"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/gopacket"
	"github.com/google/gopacket/bytediff"
	"github.com/google/gopacket/defrag/defragtest"
	"github.com/google/gopacket/defrag/sctpdefrag"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func TestDecoderDefragmentation(t *testing.T) {
	// This test relies on a curated PCAP of a single S1AP payload
	// (defragmentedMessage) fragmented over several SCTP frames (fragmentedPCAP).
	dataSource, err := pcapgo.NewNgReader(bytes.NewReader(fragmentedPCAP), pcapgo.DefaultNgReaderOptions)
	if err != nil {
		t.Fatalf("Failed to open fragmented PCAP: %v", err)
	}
	reassembled := defragWithDecoder(t, dataSource, layers.LayerTypeEthernet)
	if reassembled == nil {
		t.Fatalf("Defragmenter did not reassemble the message")
	}

	// We check that the reassembled message is as expected.
	if !bytes.Equal(reassembled.Payload(), defragmentedMessage) {
		diff := bytediff.Diff(reassembled.Payload(), defragmentedMessage)
		t.Errorf("Reassembly produced the wrong message (BASH-colorized diff, got->want):\n%v\n---PACKET (reassembled)---\n%v", bytediff.BashOutput.String(diff), gopacket.LayerDump(reassembled))
	}

	// And that the synthetic layer is a valid SCTP DATA chunk that can be serialized
	// correctly. We achieve that by serializing the synthetic layer, then decoding a
	// DATA chunk back from the serialized buffer.
	testSerDes(t, reassembled)
}

func defragWithDecoder(t *testing.T, dataSource gopacket.PacketDataSource, decoder gopacket.Decoder) (defragmented *layers.SCTPData) {
	t.Helper()

	source := gopacket.NewPacketSource(dataSource, decoder)
	source.DecodeOptions.NoCopy = true // Defragmenter should respect nocopy semantics.

	// Defragmentation is as easy as iterating over the packets in the source and
	// calling DefragData on each one.
	defrag := sctpdefrag.NewDefragmenter(sctpdefrag.WithLogger(testLogger(t)))
	for p := range source.Packets() {
		// We safely type-assert here because we know the content of the PCAP in advance.
		// Any panics indicate the PCAP has changed while the test did not.
		assoc := sctpdefrag.NewAssociation(p.NetworkLayer(), p.TransportLayer().(*layers.SCTP))
		chunk := p.Layer(layers.LayerTypeSCTPData).(*layers.SCTPData)
		// The test helper supports packet data sources containing only a single SCTP
		// message, so we can just attempt to defrag into the return variable directly.
		var err error
		defragmented, err = defrag.DefragData(assoc, chunk)
		if err != nil {
			t.Logf("Decoded chunk = %v", gopacket.LayerString(chunk))
			t.Errorf("DefragData(TSN=%v) error = %v", chunk.TSN, err)
		}
	}
	return defragmented
}

// Tests that the given synthetic SCTPData layer was constructed appropriately by
// serializing it and then deserializing again into a layer. The two layers
// should be identical, except for their BaseLayer field, which is only ever
// populated by decoded layers and ignored by the serializable layers.
func testSerDes(t *testing.T, want *layers.SCTPData) {
	t.Helper()

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, want); err != nil {
		t.Fatalf("SerializeLayers(SCTPData) = %v", err)
	}
	got := new(layers.SCTPData)
	if err := got.DecodeFromBytes(buf.Bytes(), gopacket.NilDecodeFeedback); err != nil {
		t.Fatalf("DecodeFromBytes(SCTPData) = %v", err)
	}
	var cmpOpts = []cmp.Option{
		// Ignore BaseLayer, which is not part of the synthesized SCTPData layer.
		cmpopts.IgnoreTypes(layers.BaseLayer{}),
	}
	if diff := cmp.Diff(want, got, cmpOpts...); diff != "" {
		t.Errorf("DATA chunk did not serialize->deserialize correctly (-want +got):\n%v", diff)
	}
}

func TestDecodingLayerDefragmentation(t *testing.T) {
	// This test relies on a curated PCAP of a single S1AP payload
	// (defragmentedMessage) fragmented over several SCTP frames (fragmentedPCAP).
	dataSource, err := pcapgo.NewNgReader(bytes.NewReader(fragmentedPCAP), pcapgo.DefaultNgReaderOptions)
	if err != nil {
		t.Fatalf("Failed to open fragmented PCAP: %v", err)
	}

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet)
	parser.AddDecodingLayer(&layers.Ethernet{})
	var ip layers.IPv4
	parser.AddDecodingLayer(&ip)
	var sctp layers.SCTP
	parser.AddDecodingLayer(&sctp)
	var payload sctpdefrag.BundleContainer
	parser.AddDecodingLayer(&payload)

	// Defragmentation is as easy as iterating over the packets in the source and
	// calling DefragData on each one.
	var reassembled *layers.SCTPData
	defrag := sctpdefrag.NewDefragmenter(sctpdefrag.WithLogger(testLogger(t)))
	for {
		packetData, _, err := dataSource.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("ReadPacketData() error = %v", err)
		}

		var decoded []gopacket.LayerType
		if err := parser.DecodeLayers(packetData, &decoded); err != nil {
			t.Fatalf("DecodeLayers() error = %v", err)
		}
		if decoded[len(decoded)-1] != gopacket.LayerTypePayload {
			t.Fatalf("DecodeLayers() decoded = %v, want BundleContainer", decoded)
		}

		assoc := sctpdefrag.NewAssociation(&ip, &sctp)
		// We are only interested in DATA chunks at this test.
		for _, c := range payload.ChunksOf(layers.SCTPChunkTypeData) {
			var chunk layers.SCTPData
			if err := chunk.DecodeFromBytes(c.LayerContents(), gopacket.NilDecodeFeedback); err != nil {
				t.Fatalf("SCTPData.DecodeFromBytes(): %v", err)
			}

			reassembled, err = defrag.DefragData(assoc, &chunk)
			if err != nil {
				t.Logf("Decoded chunk = %v", gopacket.LayerString(&chunk))
				t.Errorf("DefragData(TSN=%v): %v", chunk.TSN, err)
			}
		}
	}
	if reassembled == nil {
		t.Fatalf("Defragmenter did not reassemble the message")
	}

	// We check that the reassembled message is as expected.
	if !bytes.Equal(reassembled.Payload(), defragmentedMessage) {
		diff := bytediff.Diff(reassembled.Payload(), defragmentedMessage)
		t.Errorf("Reassembly produced the wrong message (BASH-colorized diff, got->want):\n%v\n---PACKET (reassembled)---\n%v", bytediff.BashOutput.String(diff), gopacket.LayerDump(reassembled))
	}

	// And that the synthetic layer is a valid SCTP DATA chunk that can be serialized
	// correctly. We achieve that by serializing the synthetic layer, then decoding a
	// DATA chunk back from the serialized buffer.
	testSerDes(t, reassembled)
}

// This PCAP contains three Ethernet frames that contain a single S1AP message
// fragmented over three SCTP DATA chunks, with chunk padding on the last frame.
//
// Reassembled SCTP Fragments (2727 bytes, 3 fragments):
//
//	Frame: 1, payload: 0-1359 (1360 bytes)
//	Frame: 2, payload: 1360-2719 (1360 bytes)
//	Frame: 3, payload: 2720-2726 (7 bytes)
//
// Frame #1
//
//	DATA chunk (ordered, first segment, TSN: 0, SID: 1, SSN: 64042, PPID: 18, payload length: 1360 bytes)
//	  Chunk type: DATA (0)
//	  Chunk flags: 0x02
//	  Chunk length: 1376
//	  Transmission sequence number (relative): 0
//	  Transmission sequence number (absolute): 462400454
//	  Stream identifier: 0x0001
//	  Stream sequence number: 64042
//	  Payload protocol identifier: S1 Application Protocol (S1AP) (18)
//
// Frame #2
//
//	DATA chunk (ordered, middle segment, TSN: 1, SID: 1, SSN: 64042, PPID: 18, payload length: 1360 bytes)
//	  Chunk type: DATA (0)
//	  Chunk flags: 0x00
//	  Chunk length: 1376
//	  Transmission sequence number (relative): 1
//	  Transmission sequence number (absolute): 462400455
//	  Stream identifier: 0x0001
//	  Stream sequence number: 64042
//	  Payload protocol identifier: S1 Application Protocol (S1AP) (18)
//
// Frame #3:
//
//	DATA chunk (ordered, last segment, TSN: 2, SID: 1, SSN: 64042, PPID: 18, payload length: 7 bytes)
//	  Chunk type: DATA (0)
//	  Chunk flags: 0x01
//	  Chunk length: 23
//	  Transmission sequence number (relative): 2
//	  Transmission sequence number (absolute): 462400456
//	  Stream identifier: 0x0001
//	  Stream sequence number: 64042
//	  Payload protocol identifier: S1 Application Protocol (S1AP) (18)
//	  Chunk padding: 00
//
//go:embed testdata/fragments.pcapng
var fragmentedPCAP []byte

//go:embed testdata/fragments-reassembled.bin
var defragmentedMessage []byte

func TestOutOfOrderChunks(t *testing.T) {
	var (
		// Any message will do.
		message = []byte("🎶 “Never gonna give you up, never gonna let you down…” 🎶")
	)

	// This test shuffles the DATA chunks so they are processed out of order.
	dataSource, err := defragtest.DataSource(
		defragtest.TemplateFunc(renderSCTPDataChunk),
		message,
		defragtest.WithFragments(5),
		defragtest.WithOrder(defragtest.ShuffleOrder),
		// We use an arbitrary association because this test cares about the order, not about
		// the associations themselves.
		defragtest.WithLayers(baseLayersForAssociation(net.IPv4(1, 1, 1, 1), net.IPv4(1, 1, 1, 1), 3, 4, 5)...),
	)
	if err != nil {
		t.Fatalf("Failed to create fragmented packet data source: %v", err)
	}

	// It shouldn't matter whether we use the Decoder API of the DecodingLayerAPI.
	// For simplicity, we chose the classic one that is easier to code and review.
	completed := defragWithDecoder(t, dataSource, layers.LayerTypeEthernet)
	if completed == nil {
		t.Fatalf("Defragmenter did not reassemble the message")
	}

	// We check that the reassembled message is as expected.
	if !bytes.Equal(completed.Payload(), message) {
		diff := bytediff.Diff(completed.Payload(), message)
		t.Errorf("Reassembly produced the wrong message (BASH-colorized diff, got->want):\n%v\n---PACKET (reassembled)---\n%v", bytediff.BashOutput.String(diff), gopacket.LayerDump(completed))
	}
}

func renderSCTPDataChunk(payload []byte, position, totalFragments, _, _ int) ([]gopacket.SerializableLayer, error) {
	const baseTSN = 0x12345678
	chunk := &layers.SCTPData{
		Unordered:       false,
		BeginFragment:   position == 0,                // Set the B flag when appropriate.
		EndFragment:     position == totalFragments-1, // Set the E flag when appropriate.
		TSN:             uint32(baseTSN + position),   // Increment TSN for each chunk.
		StreamId:        1,
		StreamSequence:  2,
		PayloadProtocol: layers.SCTPProtocolReserved, // Use the reserved protocol for this test.
		UserData:        payload,
	}
	return []gopacket.SerializableLayer{chunk}, nil
}

// Generated packet data holds Ethernet frames containing a single SCTP DATA
// chunk, no SACK or other chunks included. Most of the fields of the Ethernet,
// IP, and SCTP layers are hard-coded to meaningless values.
func baseLayersForAssociation(srcIP, dstIP net.IP, srdPort, dstPort int, tag uint32) []gopacket.SerializableLayer {
	// We always use Ethernet as the link layer.
	link := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{8, 8, 8, 8, 8, 8},
		DstMAC:       net.HardwareAddr{9, 9, 9, 9, 9, 9},
		EthernetType: layers.EthernetTypeIPv4,
		Length:       0, // Fixed by serialization.
	}
	// We use IP 4/6 based on the association's peers.
	network := &layers.IPv4{
		Version:    4,
		IHL:        5, // Fixed by serialization.
		TOS:        0, // Check the spec for this field.
		Length:     0, // Fixed by serialization.
		Id:         0, // Zero for non-fragmented IP packets.
		Flags:      layers.IPv4DontFragment,
		FragOffset: 0, // SCTP packets aren't fragmented by design.
		TTL:        64,
		Protocol:   layers.IPProtocolSCTP,
		Checksum:   0, // Fixed by serialization.
		SrcIP:      srcIP,
		DstIP:      dstIP,
		Options:    nil,
		Padding:    nil,
	}

	// We always ever fragment SCTP messages in this package.
	transport := &layers.SCTP{
		SrcPort:         layers.SCTPPort(srdPort),
		DstPort:         layers.SCTPPort(dstPort),
		VerificationTag: tag,
		Checksum:        0, // Fixed by serialization.
	}

	return []gopacket.SerializableLayer{link, network, transport}
}

// TODO: test retransmission (duplicate chunks).

// TODO: test decoding same packet twice, because the Defragmenter should delete the messageContext after the first time.

// TODO: test TSN wraparound (e.g. TSN=0xFFFFFFFF, TSN=0x00000000).

// We remember that for this test order doesn’t matter because a Defragmenter
// may receive all chunks out of order and will sort them internally before
// reassembling them.
//
// Reassembly is attempted only when both the B and E chunks are present, and
// there are enough chunks in between to attempt reassembly.
//
// There's no point in testing chunks with the same TSN, as they’re considered
// duplicates and are ignored by the Defragmenter. This behaviour is already
// tested in TestRetransmission (also behaves differently).
func TestInconsistentTSN(t *testing.T) {
	// To keep test declarations simple, we omit all none essential fields of the
	// SCTPData chunk, such as PPID, SID, SSN, etc.
	header := layers.SCTPChunk{
		Type:         layers.SCTPChunkTypeData,
		Length:       16,
		ActualLength: 16,
	}
	chunks := []*layers.SCTPData{
		{SCTPChunk: header, TSN: 1, BeginFragment: true}, // First chunk, B flag set.
		{SCTPChunk: header, TSN: 2},                      // Second chunk, incremented TSN.
		{SCTPChunk: header, TSN: 100},                    // Third chunk, TSN too high, which prevents reassembly.
		{SCTPChunk: header, TSN: 4, EndFragment: true},   // Final chunk, E flag set.
	}

	var defrag = sctpdefrag.NewDefragmenter()
	for _, chunk := range chunks {
		// Use the zero association because this test cares about the TSNs, not about
		// the associations themselves; associations are just part of the API.
		_, err := defrag.DefragData(sctpdefrag.Association{}, chunk)
		if err != nil {
			// We expect an error because we shouldn't have a chunk with TSN=100 in the range
			// of 1-4, which is the range of TSNs for the first and last chunks.
			return
		}
	}
	t.Errorf("DefragData() error = nil, want a non-nil error due to inconsistent TSN")
}

func testLogger(t *testing.T, level slog.Level) *slog.Logger {
	w := (*testWriter)(t)
	h := slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug})
	return slog.New(h)
}

type testWriter testing.T

func (t *testWriter) Write(p []byte) (n int, err error) {
	s := string(p)
	s = strings.TrimSpace(s)
	t.Log(s)
	return len(p), nil
}
