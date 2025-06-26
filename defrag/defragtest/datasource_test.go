package defragtest

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/gopacket"
)

func TestPacketOrdering(t *testing.T) {
	var data = []byte{1, 2, 3, 4, 5} // Fixed for all test-cases.
	var tests = []struct {
		order     Order
		fragments []gopacket.Fragment
	}{
		{
			order:     SequentialOrder,
			fragments: []gopacket.Fragment{{1, 2}, {3, 4}, {5}},
		},
		{
			order:     ReverseOrder,
			fragments: []gopacket.Fragment{{5}, {3, 4}, {1, 2}},
		},
		{
			order:     ShuffleOrder,
			fragments: []gopacket.Fragment{{3, 4}, {1, 2}, {5}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.order.String(), func(t *testing.T) {
			// Create a synthetic packet data source yielding packets in the desired order.
			template := TemplateFunc(RenderGenericFragment)
			opts := []Option{
				WithOrder(tt.order),
				WithFragments(3), // Fixed for all test-cases.
			}
			dataSource, err := DataSource(template, data, opts...)
			if err != nil {
				t.Fatalf("DataSource() failed: %v", err)
			}

			testDataSourceFragments(t, dataSource, tt.fragments)
		})
	}
}

// RenderGenericFragment is a simple template function used in tests. It wraps
// payloads in a generic gopacket.Fragment layer without any protocol-specific
// fragmentation logic.
func RenderGenericFragment(payload []byte, position, totalFragments, offset, totalBytes int) ([]gopacket.SerializableLayer, error) {
	_ = position       // Unused in this minimal implementation.
	_ = totalFragments // Unused in this minimal implementation.
	_ = offset         // Unused in this minimal implementation.
	_ = totalBytes     // Unused in this minimal implementation.
	frag := gopacket.Fragment(payload)
	return []gopacket.SerializableLayer{&frag}, nil
}

// Call testDataSourceFragments to verify that the given PacketDataSource yields
// fragments in the expected order. It takes []gopacket.Fragment rather than
// [][]byte because it is designed to work in tandem with the RenderGenericFragment
// template function.
func testDataSourceFragments(t *testing.T, dataSource *FragmentSource, wantFragments []gopacket.Fragment) {
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

	for i := range dataSource.TotalFragments() {
		data, err := dataSource.ReadFragmentData(i)
		if err != nil {
			t.Errorf("ReadFragmentData(%d) error = %v", i, err)
			continue
		}
		frag := gopacket.Fragment(data)
		if diff := cmp.Diff(wantFragments[i], frag); diff != "" {
			t.Errorf("ReadFragmentData(%d) mismatch (-want +got):\n%s", i, diff)
		}
	}
}

func TestFragmentedDataSource(t *testing.T) {
	var (
		template = TemplateFunc(RenderGenericFragment)
		data     = []byte{1, 2, 3, 4, 5}
	)

	// TestPacketOrdering covers valid uses of WithOrder, and the Example covers
	// valid uses of WithLayers and WithCaptureTimestamp.
	var tests = []struct {
		description string // Completes the sentence "Testing DataSource() with ...".
		options     []Option
		fragments   []gopacket.Fragment
	}{
		{
			description: "as few fragments as possible",
			options:     []Option{WithFragments(1)},
			fragments:   []gopacket.Fragment{{1, 2, 3, 4, 5}},
		},
		{
			description: "as many fragments as possible",
			options:     []Option{WithFragments(1)},
			fragments:   []gopacket.Fragment{{1, 2, 3, 4, 5}},
		},
		{
			description: "exact fragment size",
			options:     []Option{WithMaxFragmentSize(5)},
			fragments:   []gopacket.Fragment{{1, 2, 3, 4, 5}},
		},
		{
			description: "bigger fragment size",
			options:     []Option{WithMaxFragmentSize(6)},
			fragments:   []gopacket.Fragment{{1, 2, 3, 4, 5}},
		},
		{
			description: "smaller fragment size",
			options:     []Option{WithMaxFragmentSize(4)},
			fragments:   []gopacket.Fragment{{1, 2, 3, 4}, {5}},
		},
	}

	for _, tt := range tests {
		t.Logf("Testing DataSource() with %s", tt.description)
		dataSource, err := DataSource(template, data, tt.options...)
		if err != nil {
			t.Errorf("DataSource() failed: %v", err)
			continue
		}
		testDataSourceFragments(t, dataSource, tt.fragments)
	}
}

func TestInvalidOptions(t *testing.T) {
	var (
		template = TemplateFunc(RenderGenericFragment)
		data     = []byte{1, 2, 3, 4, 5}
	)

	var invalidOptions = []struct {
		description string // Completes the sentence "Testing DataSource() with ...".
		options     []Option
	}{
		{
			description: "missing fragment options",
			options:     []Option{},
		},
		{
			description: "both Fragments and FragmentSize",
			options: []Option{
				WithFragments(1),
				WithMaxFragmentSize(1),
			},
		},
		{
			description: "not enough data for number of fragments",
			options:     []Option{WithFragments(6)},
		},
		{
			description: "negative fragments",
			options:     []Option{WithFragments(-1)},
		},
		{
			description: "negative fragment size",
			options:     []Option{WithMaxFragmentSize(-1)},
		},
		{
			description: "an unknown order",
			options: []Option{
				WithOrder(Order(3)),
				WithFragments(1), // Must be specified to trigger the unknown order (3).
			},
		},
	}
	for _, tt := range invalidOptions {
		t.Logf("Testing DataSource() with %s", tt.description)
		_, err := DataSource(template, data, tt.options...)
		if err == nil {
			t.Errorf("DataSource() succeeded unexpectedly")
			continue
		}
		t.Logf("DataSource() error = %v", err)
	}
}
