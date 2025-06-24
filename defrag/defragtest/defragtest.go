// Package defragtest provides utilities for testing implementations of packet
// defragmentation. It creates synthetic packet data sources that split payloads
// into fragments, allowing defragmentation logic to be tested in isolation.
//
// The primary entry point is the [Fragment] function, which takes a payload and
// splits it into multiple packets according to the specified options. Each
// fragment is transformed into a serializable layer by a [Fragmenter]
// implementation.
package defragtest

import (
	"fmt"
	"io"
	"iter"
	"math"
	"slices"
	"time"

	"github.com/google/gopacket"
)

// Fragmenter transforms a fragment payload into a protocol-specific layer that
// can be serialized into a packet.
//
// The [Fragment] function uses a Fragmenter to create appropriate layers for
// each fragment of the original data. For example, an IPv4 fragmenter might
// create layers.IPv4 instances with appropriate fragmentation flags, while an
// SCTP fragmenter might create layers.SCTPData chunks with begin/end fragment
// indicators.
type Fragmenter interface {
	// FragmentLayer return the protocol-specific layer containing the given fragment
	// payload. The index parameter indicates this fragment's position (0-based)
	// within the sequence, and total specifies the total number of fragments.
	// Implementations should return an error if the fragment cannot be created.
	FragmentLayer(payload []byte, index, total int) (gopacket.SerializableLayer, error)
}

// FragmenterFunc is an adapter to allow the use of ordinary functions as
// Fragmenters.
//
// If f is a function with the appropriate signature, FragmenterFunc(f) is a
// Fragmenter that calls f.
type FragmenterFunc func(payload []byte, index, total int) (gopacket.SerializableLayer, error)

// FragmentLayer calls f(payload, index, total).
func (f FragmenterFunc) FragmentLayer(payload []byte, index, total int) (gopacket.SerializableLayer, error) {
	return f(payload, index, total)
}

// Order defines the sequence in which fragments are yielded from the synthetic
// packet data source created by Fragment.
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

// Fragment creates a synthetic packet data source that splits the given data
// into multiple fragments, each wrapped in a packet. The source parameter
// determines how each fragment payload is transformed into a serializable layer.
//
// The returned PacketDataSource yields packets containing the fragmented data,
// with each packet consisting of any base layers specified via [WithLayers]
// followed by the fragment layer created by the [Fragmenter].
//
// Either [WithFragments] or [WithMaxFragmentSize] must be specified in the
// options to control how the data is split. These options are mutually
// exclusive.
//
// This function returns a non-nil error when the given options are invalid or if
// it detects the given data is incompatible with the given options.
func Fragment(source Fragmenter, data []byte, opts ...Option) (gopacket.PacketDataSource, error) {
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
	if source == nil {
		return nil, fmt.Errorf("nil Fragmenter will panic")
	}
	return newFragmentDataSource(source, data, opt), nil
}

// Options configure how the [Fragment] function splits data and generates
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

// Option is a function that carried user settings for [Fragment].
type Option func(Options) Options

// WithOrder sets the order in which fragments are yielded from the packet
// data source. The default order is [SequentialOrder].
func WithOrder(order Order) Option {
	return func(options Options) Options {
		options.Order = order
		return options
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
// The Fragment function will return an error if the data has fewer bytes than
// the requested number of fragments, as it cannot create empty fragments.
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

// FragmentBytes returns an iterator over consecutive sub-slices of the given
// bytes buffer. There will be exactly as many sub-slices as specified by fragments.
// All but the last sub-slice will have the same size.
//
// Suppose a buffer of size BYTES divides evenly into FRAGMENTS sub-slices; then
// each sub-slice would contain BYTES/FRAGMENTS bytes. Otherwise, we can fill all
// but the last sub-slice evenly, with the last sub-slice containing fewer bytes.
//
// All sub-slices are clipped to have no capacity beyond their length. If the
// given message is empty, the sequence is empty: there is no empty slice in the
// sequence.
//
// FragmentBytes panics if the given number of fragments is lower than 1.
func FragmentBytes(buf []byte, fragments int) iter.Seq[[]byte] {
	// Imagine we have N buckets of the same size, and L bytes, and suppose L doesn't
	// divide evenly into N buckets. Then we can fill all but the last bucket evenly,
	// with the last bucket containing fewer bytes.
	//
	// In this case, the bytes missing from the last bucket amount exactly to the
	// modulo of L/N. By doing so, we've actually put in every bucket as
	// many bytes as rounding up the division.
	bucket := int(math.Ceil(float64(len(buf)) / float64(fragments)))
	return slices.Chunk(buf, bucket)
}

// A fragmentDataSource implements gopacket.PacketDataSource to yield fragmented
// packets in a controlled sequence.
type fragmentDataSource struct {
	Fragmenter
	Fragments [][]byte
	Cursor    int // Initialised to -1.

	Order            Order
	BaseLayers       []gopacket.SerializableLayer
	CaptureTimestamp time.Time
}

// Only call newFragmentDataSource with valid options, otherwise it will panic.
func newFragmentDataSource(source Fragmenter, data []byte, opts Options) *fragmentDataSource {
	if opts.FragmentSize != 0 {
		return &fragmentDataSource{
			Fragmenter:       source,
			Fragments:        slices.Collect(slices.Chunk(data, opts.FragmentSize)),
			Cursor:           -1,
			Order:            opts.Order,
			BaseLayers:       opts.BaseLayers,
			CaptureTimestamp: opts.CaptureTimestamp,
		}
	}
	if opts.Fragments != 0 {
		return &fragmentDataSource{
			Fragmenter:       source,
			Fragments:        slices.Collect(FragmentBytes(data, opts.Fragments)),
			Cursor:           -1,
			Order:            opts.Order,
			BaseLayers:       opts.BaseLayers,
			CaptureTimestamp: opts.CaptureTimestamp,
		}
	}
	// This won't panic if the given options are validated beforehand.
	panic("github.com/google/gopacket/defrag/defragtest: called with invalid options")
}

// ReadPacketData returns the next fragment wrapped in a packet according to the
// configured options. When all fragments have been read, it returns io.EOF.
func (ds *fragmentDataSource) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	ds.Cursor++ // Fine because Cursor is initialised to -1.
	if ds.Cursor >= len(ds.Fragments) {
		return nil, gopacket.CaptureInfo{}, io.EOF
	}

	// Each packet contains a single fragment of the entire data, carried by the
	// user-defined layer.
	position := ds.Order.Transform(ds.Cursor, len(ds.Fragments))
	payload := ds.Fragments[position]
	frag, err := ds.FragmentLayer(payload, position, len(ds.Fragments))
	if err != nil {
		return nil, gopacket.CaptureInfo{}, fmt.Errorf("fragment layer: %w", err)
	}
	// The user-defined base layers are prepended before the fragment's layer.
	layers := append(ds.BaseLayers, frag)

	// We serialise the fragment's layer, along with any base layers provided by the
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
