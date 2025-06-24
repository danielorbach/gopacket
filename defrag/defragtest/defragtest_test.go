package defragtest_test

import (
	"fmt"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/gopacket"
	"github.com/google/gopacket/defrag/defragtest"
)

func TestPacketOrdering(t *testing.T) {
	var data = []byte{1, 2, 3, 4, 5} // Fixed for all test-cases.
	var tests = []struct {
		order     defragtest.Order
		fragments []gopacket.Fragment
	}{
		{
			order:     defragtest.SequentialOrder,
			fragments: []gopacket.Fragment{{1, 2}, {3, 4}, {5}},
		},
		{
			order:     defragtest.ReverseOrder,
			fragments: []gopacket.Fragment{{5}, {3, 4}, {1, 2}},
		},
		{
			order:     defragtest.ShuffleOrder,
			fragments: []gopacket.Fragment{{3, 4}, {1, 2}, {5}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.order.String(), func(t *testing.T) {
			// Create a synthetic packet data source yielding packets in the desired order.
			fragmenter := defragtest.FragmenterFunc(FragmentLayer)
			opts := []defragtest.Option{
				defragtest.WithOrder(tt.order),
				defragtest.WithFragments(3), // Fixed for all test-cases.
			}
			dataSource, err := defragtest.Fragment(fragmenter, data, opts...)
			if err != nil {
				t.Fatalf("Fragment() failed: %v", err)
			}

			testDataSourceFragments(t, dataSource, tt.fragments)
		})
	}
}

// Call testDataSourceFragments to verify that the given PacketDataSource yields
// fragments in the expected order. It takes []gopacket.Fragment rather than
// [][]byte because it is designed to work in tandem with the FragmentLayer
// fragmenter.
func testDataSourceFragments(t *testing.T, dataSource gopacket.PacketDataSource, wantFragments []gopacket.Fragment) {
	t.Helper()

	// Collect fragments from the synthetic packet data source.
	var gotFragments []gopacket.Fragment
	source := gopacket.NewPacketSource(dataSource, gopacket.DecodeFragment)
	for p := range source.Packets() {
		frag := p.Layer(gopacket.LayerTypeFragment).(*gopacket.Fragment)
		gotFragments = append(gotFragments, frag.Payload())
	}

	if diff := cmp.Diff(gotFragments, wantFragments); diff != "" {
		t.Errorf("Fragments mismatch (-want +got):\n%s", diff)
	}
}

func TestFragmentOptions(t *testing.T) {
	var (
		fragmenter = defragtest.FragmenterFunc(FragmentLayer)
		data       = []byte{1, 2, 3, 4, 5}
	)

	// Valid uses of WithOrder are covered by TestPacketOrdering.
	// Valid uses of WithLayers and WithCaptureTimestamp are covered by Example.
	var validOptions = []struct {
		description string // Completes the sentence "Testing Fragment() with ...".
		options     []defragtest.Option
		fragments   []gopacket.Fragment
	}{
		{
			description: "as few fragments as possible",
			options:     []defragtest.Option{defragtest.WithFragments(1)},
			fragments:   []gopacket.Fragment{{1, 2, 3, 4, 5}},
		},
		{
			description: "as many fragments as possible",
			options:     []defragtest.Option{defragtest.WithFragments(1)},
			fragments:   []gopacket.Fragment{{1, 2, 3, 4, 5}},
		},
		{
			description: "exact fragment size",
			options:     []defragtest.Option{defragtest.WithMaxFragmentSize(5)},
			fragments:   []gopacket.Fragment{{1, 2, 3, 4, 5}},
		},
		{
			description: "bigger fragment size",
			options:     []defragtest.Option{defragtest.WithMaxFragmentSize(6)},
			fragments:   []gopacket.Fragment{{1, 2, 3, 4, 5}},
		},
		{
			description: "smaller fragment size",
			options:     []defragtest.Option{defragtest.WithMaxFragmentSize(4)},
			fragments:   []gopacket.Fragment{{1, 2, 3, 4}, {5}},
		},
	}
	t.Run("Valid", func(t *testing.T) {
		for _, tt := range validOptions {
			t.Logf("Testing Fragment() with %s", tt.description)
			dataSource, err := defragtest.Fragment(fragmenter, data, tt.options...)
			if err != nil {
				t.Errorf("Fragment() failed: %v", err)
				continue
			}
			testDataSourceFragments(t, dataSource, tt.fragments)
		}
	})

	var invalidOptions = []struct {
		description string // Completes the sentence "Testing Fragment() with ...".
		options     []defragtest.Option
	}{
		{
			description: "missing fragment options",
			options:     []defragtest.Option{},
		},
		{
			description: "both Fragments and FragmentSize",
			options: []defragtest.Option{
				defragtest.WithFragments(1),
				defragtest.WithMaxFragmentSize(1),
			},
		},
		{
			description: "not enough data for number of fragments",
			options:     []defragtest.Option{defragtest.WithFragments(6)},
		},
		{
			description: "negative fragments",
			options:     []defragtest.Option{defragtest.WithFragments(-1)},
		},
		{
			description: "negative fragment size",
			options:     []defragtest.Option{defragtest.WithMaxFragmentSize(-1)},
		},
		{
			description: "an unknown order",
			options: []defragtest.Option{
				defragtest.WithOrder(defragtest.Order(3)),
				defragtest.WithFragments(1), // Must be specified to trigger unknown order.
			},
		},
	}
	t.Run("Invalid", func(t *testing.T) {
		for _, tt := range invalidOptions {
			t.Logf("Testing Fragment() with %s", tt.description)
			_, err := defragtest.Fragment(fragmenter, data, tt.options...)
			if err == nil {
				t.Errorf("Fragment() succeeded unexpectedly")
				continue
			}
			t.Logf("Fragment() error = %v", err)
		}
	})
}

func TestFragmentingBytes(t *testing.T) {
	var tests = []struct {
		message []byte
		chunks  int
		want    [][]byte
	}{
		{
			message: []byte("123456789ABCDEF"),
			chunks:  1,
			want: [][]byte{
				[]byte("123456789ABCDEF"),
			},
		},
		{
			message: []byte("123456789ABCDEF"),
			chunks:  2,
			want: [][]byte{
				[]byte("12345678"),
				[]byte("9ABCDEF"),
			},
		},
		{
			message: []byte("123456789ABCDEF"),
			chunks:  3,
			want: [][]byte{
				[]byte("12345"),
				[]byte("6789A"),
				[]byte("BCDEF"),
			},
		},
	}

	for _, tt := range tests {
		t.Logf("Splitting %d bytes into %d chunks", len(tt.message), tt.chunks)
		if len(tt.want) != tt.chunks {
			// This panic is here to protect against unintentional modifications that void
			// the test cases.
			panic(fmt.Sprintf("Invalid test-case splits into wrong number of chunks: chunks=%d, len(want)=%d", tt.chunks, len(tt.want)))
		}
		parts := slices.Collect(defragtest.FragmentBytes(tt.message, tt.chunks))
		if diff := cmp.Diff(parts, tt.want); diff != "" {
			t.Errorf("FragmentUserData() mismatch (-want +got):\n%s", diff)
		}
	}
}
