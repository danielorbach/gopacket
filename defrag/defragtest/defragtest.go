// Package defragtest provides utilities for testing implementations of packet
// defragmentation. It creates synthetic packet data sources that split payloads
// into fragments, allowing defragmentation logic to be tested in isolation.
//
// The primary entry point is the [DataSource] function, which takes a payload
// and splits it into multiple packets according to the specified options. Each
// fragment is transformed into a serializable layer according to
// protocol-specific [Template] implementation.
package defragtest

import (
	"iter"
	"math"
	"slices"

	"github.com/google/gopacket"
)

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

// A Template transforms a fragment payload into protocol-specific layers that
// can be serialized into a packet.
//
// The [DataSource] function uses a Template to render appropriate layers for
// each fragment of the original data. For example, an IPv4 template might create
// layers.IPv4 instances with appropriate fragmentation flags, while an SCTP
// template might create layers.SCTPData chunks with begin/end fragment
// indicators.
//
// Returning multiple layers provides flexibility for protocols that require
// additional encapsulation or metadata layers alongside the fragment data.
// For instance, some protocols might need to include both a control layer
// with fragmentation metadata and a separate data layer containing the actual
// payload. This design allows templates to accurately represent complex
// protocol structures without forcing artificial layer consolidation.
type Template interface {
	// RenderFragment return the protocol-specific layers containing the given
	// fragmented payload.
	//
	// The index parameter indicates this fragment's position (0-based) within the
	// sequence, and total specifies the total number of fragments. Implementations
	// should return an error if the fragment cannot be rendered.
	RenderFragment(payload []byte, index, total int) ([]gopacket.SerializableLayer, error)
}

// TemplateFunc is an adapter to allow the use of ordinary functions as
// Templates.
//
// If f is a function with the appropriate signature, TemplateFunc(f) is a
// [Template] that calls f.
type TemplateFunc func(payload []byte, index, total int) ([]gopacket.SerializableLayer, error)

// RenderFragment calls f(payload, index, total).
func (f TemplateFunc) RenderFragment(payload []byte, index, total int) ([]gopacket.SerializableLayer, error) {
	return f(payload, index, total)
}
