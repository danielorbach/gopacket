package defragtest

import (
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/google/gopacket"
)

// DataSource creates a synthetic packet data source that splits the given data
// into multiple fragments, each wrapped in a packet. The template parameter
// determines how each fragment payload is rendered into serializable layers.
//
// The returned PacketDataSource yields packets containing the fragmented data,
// with each packet consisting of any base layers specified via [WithLayers]
// followed by the fragment layers rendered by the [Template].
//
// Either [WithFragments] or [WithMaxFragmentSize] must be specified in the
// options to control how the data is split. These options are mutually
// exclusive.
//
// This function returns a non-nil error when the given options are invalid or if
// it detects the given data is incompatible with the given options.
func DataSource(template Template, data []byte, opts ...Option) (gopacket.PacketDataSource, error) {
	var opt Options
	for _, o := range opts {
		opt = o(opt)
	}
	if err := opt.Validate(); err != nil {
		return nil, fmt.Errorf("invalid options: %w", err)
	}
	if opt.Fragments != 0 && len(data) < opt.Fragments {
		return nil, fmt.Errorf("data is too small for %d fragments", opt.Fragments)
	}
	if template == nil {
		return nil, fmt.Errorf("nil Template will panic")
	}

	// The given Options are validated beforehand, meaning either opt.FragmentSize or
	// opt.Fragments is non-zero.
	var fragments [][]byte
	if opt.FragmentSize != 0 {
		fragments = slices.Collect(slices.Chunk(data, opt.FragmentSize))
	}
	if opt.Fragments != 0 {
		fragments = slices.Collect(FragmentBytes(data, opt.Fragments))
	}
	return &fragmentDataSource{
		Template:         template,
		Fragments:        fragments,
		Cursor:           -1,
		Order:            opt.Order,
		BaseLayers:       opt.BaseLayers,
		CaptureTimestamp: opt.CaptureTimestamp,
	}, nil
}

// Option is a function that carried user settings for [DataSource].
type Option func(Options) Options

// Options configure how the [DataSource] function splits data and generates
// packets.
//
// Use [WithFragments] or [WithMaxFragmentSize] to control fragmentation,
// [WithOrder] to control fragment ordering, [WithLayers] to add base protocol
// layers, and [WithCaptureTimestamp] to set packet timestamps.
type Options struct {
	// The exact number of fragments to split the payload into.
	//
	// This option is mutually exclusive with [FragmentSize].
	Fragments int
	// The maximal number of bytes per fragment of the payload.
	//
	// This option is mutually exclusive with [Fragments].
	FragmentSize int

	// Defines the order in which the synthetic packet data source would yield the
	// fragments.
	Order Order

	// These layers are written to each packet before every fragmented payload.
	BaseLayers []gopacket.SerializableLayer

	// Sets the [gopacket.CaptureInfo.Timestamp] of fragmented packets.
	CaptureTimestamp time.Time
}

// Validate checks that the options are internally consistent and valid.
//
// It returns an error if both Fragments and FragmentSize are set, or if
// neither is set.
func (o Options) Validate() error {
	if o.Fragments == 0 && o.FragmentSize == 0 {
		return fmt.Errorf("either Fragments or FragmentSize must be set")
	}
	if o.Fragments > 0 && o.FragmentSize > 0 {
		return fmt.Errorf("both Fragments and FragmentSize cannot be set")
	}
	if o.Fragments < 0 {
		return fmt.Errorf("when set Fragments must be non-negative")
	}
	if o.FragmentSize < 0 {
		return fmt.Errorf("when set FragmentSize must be non-negative")
	}
	if o.Order < SequentialOrder || o.Order > ShuffleOrder {
		return fmt.Errorf("invalid order: %v", o.Order)
	}
	return nil
}

// WithOrder sets the order in which fragments are yielded from the packet
// data source. The default order is [SequentialOrder].
func WithOrder(order Order) Option {
	return func(options Options) Options {
		options.Order = order
		return options
	}
}

// Order defines the sequence in which fragments are yielded from the synthetic
// packet data source created by [DataSource].
type Order int

const (
	// SequentialOrder yields fragments in their natural order (0, 1, 2, ...).
	SequentialOrder Order = iota
	// ReverseOrder yields fragments in reverse order (n-1, n-2, ..., 0).
	ReverseOrder
	// ShuffleOrder yields fragments in a deterministic shuffled pattern,
	// alternating between adjacent fragments.
	ShuffleOrder
)

// String returns a human-readable representation of the fragment order.
func (o Order) String() string {
	switch o {
	case SequentialOrder:
		return "sequential"
	case ReverseOrder:
		return "reverse"
	case ShuffleOrder:
		return "shuffle"
	}
	return fmt.Sprintf("Order(%d)", int(o))
}

// Transform maps a logical fragment index to its position in the yielded
// sequence based on the ordering strategy.
//
// The ordinal parameter represents the logical position (0-based), and total is
// the total number of fragments. The method returns the actual index at which
// this fragment will appear.
func (o Order) Transform(ordinal, total int) (position int) {
	switch o {
	case SequentialOrder:
		return ordinal
	case ReverseOrder:
		return total - ordinal - 1
	case ShuffleOrder:
		if ordinal%2 == 0 {
			return min(ordinal+1, total-1) // Do not overflow.
		} else {
			return ordinal - 1
		}
	default:
		panic(fmt.Sprintf("github.com/google/gopacket/defrag/defragtest: unknown fragments order %v", o))
	}
}

// WithMaxFragmentSize sets the maximum number of bytes per fragment. The data
// will be split into as many fragments as needed, with each fragment containing
// at most the specified number of bytes. The last fragment may contain fewer
// bytes.
//
// This option is mutually exclusive with [WithFragments].
func WithMaxFragmentSize(bytes int) Option {
	return func(options Options) Options {
		options.FragmentSize = bytes
		return options
	}
}

// WithFragments sets the exact number of fragments to split the data into. The
// data will be divided as evenly as possible, with earlier fragments potentially
// containing more bytes than later fragments if the division is not exact.
//
// The [DataSource] function will return an error if the data has fewer bytes
// than the requested number of fragments, as it cannot create empty fragments.
//
// This option is mutually exclusive with [WithMaxFragmentSize].
func WithFragments(fragments int) Option {
	return func(options Options) Options {
		options.Fragments = fragments
		return options
	}
}

// WithLayers sets the base layers that are prepended to each fragment packet.
// These layers typically include protocol headers like Ethernet and IP that
// would carry the fragmented payload in a real network scenario.
//
// If specified multiple times, the layers given in the last call take
// precedence, overriding previous calls.
func WithLayers(layers ...gopacket.SerializableLayer) Option {
	return func(options Options) Options {
		options.BaseLayers = layers
		return options
	}
}

// WithCaptureTimestamp sets the timestamp that will be used in the CaptureInfo
// for all generated packets. If not specified, the zero time value is used.
func WithCaptureTimestamp(timestamp time.Time) Option {
	return func(options Options) Options {
		options.CaptureTimestamp = timestamp
		return options
	}
}

// A fragmentDataSource implements gopacket.PacketDataSource to yield fragmented
// packets in a controlled sequence.
type fragmentDataSource struct {
	Template
	Fragments [][]byte
	Cursor    int // Initialized to -1.

	Order            Order
	BaseLayers       []gopacket.SerializableLayer
	CaptureTimestamp time.Time
}

// PositionOffset returns the byte offset of the fragment at the given position.
func (ds *fragmentDataSource) positionOffset(position int) int {
	offset := 0
	for i := 0; i < position; i++ {
		offset += len(ds.Fragments[i])
	}
	return offset
}

// TotalBytes returns the total size of all fragments combined.
func (ds *fragmentDataSource) totalBytes() int {
	totalBytes := 0
	for _, frag := range ds.Fragments {
		totalBytes += len(frag)
	}
	return totalBytes
}

// ReadPacketData returns the next fragment wrapped in a packet according to the
// configured options. When all fragments have been read, it returns io.EOF.
func (ds *fragmentDataSource) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	ds.Cursor++ // Fine because Cursor is initialized to -1.
	if ds.Cursor >= len(ds.Fragments) {
		return nil, gopacket.CaptureInfo{}, io.EOF
	}

	// Each packet contains a single fragment of the entire data, carried by the
	// user-defined layers.
	position := ds.Order.Transform(ds.Cursor, len(ds.Fragments))
	payload := ds.Fragments[position]
	offset := ds.positionOffset(position)
	totalBytes := ds.totalBytes()
	frags, err := ds.RenderFragment(payload, position, len(ds.Fragments), offset, totalBytes)
	if err != nil {
		return nil, gopacket.CaptureInfo{}, fmt.Errorf("fragment layer: %w", err)
	}
	// The user-defined base layers are prepended before the fragment's layers.
	layers := append(ds.BaseLayers, frags...)

	// We serialize the fragment's layers, along with any base layers provided by the
	// user, to generate the appropriate bytes for each packet.
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, layers...); err != nil {
		return nil, gopacket.CaptureInfo{}, fmt.Errorf("synthesize packet: %w", err)
	}

	ci := gopacket.CaptureInfo{
		Timestamp:     ds.CaptureTimestamp,
		Length:        len(buf.Bytes()),
		CaptureLength: len(buf.Bytes()),
	}
	return buf.Bytes(), ci, nil
}
