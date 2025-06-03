package sctpdefrag_test

import (
	"bytes"
	_ "embed"
	"github.com/google/gopacket"
	"github.com/google/gopacket/bytediff"
	"github.com/google/gopacket/defrag/sctpdefrag"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"reflect"
	"testing"
)

func TestDefragmentation(t *testing.T) {
	// This test relies on a curated PCAP of a single S1AP payload
	// (defragmentedMessage) fragmented over several SCTP frames (fragmentedPCAP).
	dataSource, err := pcapgo.NewNgReader(bytes.NewReader(fragmentedPCAP), pcapgo.DefaultNgReaderOptions)
	if err != nil {
		t.Fatalf("Failed to open fragmented PCAP: %v", err)
	}
	source := gopacket.NewPacketSource(dataSource, layers.LayerTypeEthernet)
	// Defragmenter should respect nocopy semantics.
	source.DecodeOptions.NoCopy = true

	// Defragmentation is as easy as iterating over the packets in the source and
	// calling DefragData on each one.
	var reassembled *layers.SCTPData
	defrag := sctpdefrag.NewDefragmenter()
	for p := range source.Packets() {
		chunk := p.Layer(layers.LayerTypeSCTPData).(*layers.SCTPData)
		reassembled, err = defrag.DefragData(chunk)
		if err != nil {
			t.Logf("Decoding %v", gopacket.LayerString(chunk))
			t.Errorf("DefragData(TSN=%v): %v", chunk.TSN, err)
		}
	}
	if reassembled == nil {
		t.Fatalf("Defragmenter did not reassemble the message")
	}

	// We check that the reassembled message is as expected.
	if !bytes.Equal(reassembled.Payload, defragmentedMessage) {
		diff := bytediff.Diff(reassembled.Payload, defragmentedMessage)
		t.Errorf("Reassembly produced the wrong message (BASH-colorized diff, got->want):\n%v\n---PACKET (reassembled)---\n%v", bytediff.BashOutput.String(diff), gopacket.LayerDump(reassembled))
	}
	// And that the synthetic layer is a valid SCTP DATA chunk that can be serialised
	// correctly. We achieve that by serialising both the header and data, then
	// decoding a DATA chunk back from the serialised buffer.
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, reassembled, gopacket.Payload(reassembled.Payload)); err != nil {
		t.Fatalf("SerializeLayers(SCTPData) = %v", err)
	}
	reconstructed := new(layers.SCTPData)
	if err := reconstructed.DecodeFromBytes(buf.Bytes(), gopacket.NilDecodeFeedback); err != nil {
		t.Fatalf("DecodeFromBytes(SCTPData) = %v", err)
	}
	if !reflect.DeepEqual(reconstructed, reassembled) {
		t.Errorf("Reassembled DATA chunk did not serialize/deserialize correctly:\n---deserialized---\n%v\n---defragmented---\n%v", gopacket.LayerDump(reconstructed), gopacket.LayerDump(reassembled))
	}
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
