package defragtest

import (
	"io"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestNaiveRetransmission(t *testing.T) {
	// Create a synthetic packet data source that yields a single packet for simplicity.
	dataSource, err := DataSource(
		TemplateFunc(RenderGenericFragment),
		[]byte{1, 2, 3, 4, 5, 6, 7, 8},
		WithFragments(1),
	)
	if err != nil {
		t.Fatalf("DataSource() failed: %v", err)
	}

	// Wrap the data source with the naive retransmission logic and exhausting it.
	retransmitSource := Retransmit(dataSource)
	packet1, ci1, err := retransmitSource.ReadPacketData()
	if err != nil {
		t.Fatalf("ReadPacketData() failed: %v", err)
	}
	packet2, ci2, err := retransmitSource.ReadPacketData()
	if err != nil {
		t.Fatalf("ReadPacketData() again failed: %v", err)
	}

	// Both calls to ReadPacketData() should return the same results.
	if diff := cmp.Diff(packet1, packet2); diff != "" {
		t.Errorf("Packets data mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(ci1, ci2); diff != "" {
		t.Errorf("CaptureInfo mismatch (-want +got):\n%s", diff)
	}
	// Reading again should exhaust the data source.
	_, _, err = retransmitSource.ReadPacketData()
	if err != io.EOF {
		t.Errorf("ReadPacketData() = %v, want io.EOF", err)
	}
}
