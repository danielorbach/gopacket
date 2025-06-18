package sctpdefrag

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// BundleContainer is an intermediary decoding layer for SCTP payloads containing
// bundled chunks. It provides efficient access to chunks without allocating new
// layers for each chunk.
//
// BundleContainer implements gopacket.DecodingLayer, allowing it to be used with
// gopacket.DecodingLayerParser for high-performance packet processing. The
// container reuses an internal slice of layers.SCTPChunk headers between calls
// to DecodeFromBytes, further minimising allocations as much as possible.
//
// Typical usage:
//
//	var bundle BundleContainer
//	parser.AddDecodingLayer(&bundle)
//	// ... decode packet ...
//	for _, chunk := range bundle.Chunks() {
//	    switch chunk.Type {
//	    case layers.SCTPChunkTypeData:
//	        var data layers.SCTPData
//	        data.DecodeFromBytes(chunk.LayerContents(), gopacket.NilDecodeFeedback)
//	        // Process data chunk
//	    }
//	}
type BundleContainer struct {
	// Contains the raw byte data of the SCTP payload for processing and decoding.
	data []byte
	// Contains the decoded headers of chunks in the SCTP payload. This slice is
	// reused between calls to DecodeFromBytes for efficiency.
	chunks []layers.SCTPChunk
}

// DecodeFromBytes parses an SCTP payload containing bundled chunks. It extracts
// the common header information for each chunk without fully decoding the
// chunk-specific fields.
//
// The method reuses internal storage to minimise allocations. If any error
// occurs during chunk header decoding, the method returns immediately with the
// error.
//
// This method is called by gopacket.DecodingLayerParser when processing packets.
func (b *BundleContainer) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	// Store the entire payload as contents.
	b.data = data
	// Clear chunks slice while preserving capacity.
	b.chunks = b.chunks[:0]

	// Decode all chunk headers from the SCTP payload.
	remaining := data
	for len(remaining) > 0 {
		var chunk layers.SCTPChunk
		if err := chunk.DecodeFromBytes(remaining, df); err != nil {
			// If we can't decode a chunk header, stop processing.
			offset := len(data) - len(remaining)
			return fmt.Errorf("decode common chunk header at offset %d: %w", offset, err)
		}
		// DecodeFromBytes sets the SCTPChunk's Payload to contain the remaining portion
		// of undecoded data. We use it to advance our cursor into the data buffer to the
		// start of the next chunk. If the data buffer does not accommodate the entire
		// chunk, then SCTPChunk.DecodeFromBytes would've failed earlier
		//
		// We must zero the Payload before placing the SCTPChunk into the internal slice
		// of headers because it provides enhances isolation for each chunk, preventing
		// users from using the data improperly.
		remaining = chunk.Payload
		chunk.Payload = nil
		b.chunks = append(b.chunks, chunk)
	}

	return nil
}

// CanDecode returns the set of layer types that this DecodingLayer can decode. A
// BundleContainer decodes generic payload data containing SCTP chunks.
func (b *BundleContainer) CanDecode() gopacket.LayerClass {
	return gopacket.LayerTypePayload
}

// LayerContents returns the raw byte data of the SCTP payload stored in the
// BundleContainer.
func (b *BundleContainer) LayerContents() []byte {
	return b.data
}

// NextLayerType returns gopacket.LayerTypeZero as BundleContainer is a terminal
// layer that does not lead to additional layers.
func (b *BundleContainer) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypeZero
}

// LayerPayload returns nil because an SCTP packet may contain a bundle of chunks
// as payload, and nothing else, making this layer a terminal one.
//
// Additional communication layers carried on top of DATA chunks are accessible
// using a Defragmenter.
func (b *BundleContainer) LayerPayload() []byte {
	return nil
}

// LayerType returns gopacket.LayerTypePayload to identify this layer in decoded
// layer lists as the terminal layer containing the payload of SCTP packets.
func (b *BundleContainer) LayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// Chunks returns the slice of common SCTP chunk fields (also known as headers)
// that were decoded from the payload.
//
// The returned slice is reused between calls to DecodeFromBytes and should not
// be modified or stored beyond the next call to DecodeFromBytes. The slice
// contains basic chunk information (type, flags, length) without the
// chunk-specific fields decoded.
//
// To fully decode a specific chunk, use its LayerContents() method with the
// appropriate chunk type's DecodeFromBytes method:
//
//	for _, chunk := range bundle.Chunks() {
//	    if chunk.Type == layers.SCTPChunkTypeData {
//	        var data layers.SCTPData
//	        data.DecodeFromBytes(chunk.LayerContents(), gopacket.NilDecodeFeedback)
//	    }
//	}
func (b *BundleContainer) Chunks() []layers.SCTPChunk {
	return b.chunks
}

func ChunksFrom(payload []byte) func(yield func(i int, chunk gopacket.Layer) bool) {
	return func(yield func(i int, chunk gopacket.Layer) bool) {
		for i := 0; len(payload) != 0; i++ {
			failure := &DecodeChunkFailure{data: payload}
			chunkType := layers.SCTPChunkType(payload[0])
			switch chunkType {
			case layers.SCTPChunkTypeData:
				var sctpData layers.SCTPData
				if err := sctpData.DecodeFromBytes(payload, failure); err != nil {
					failure.err = err
					yield(i, failure)
					return
				}
				if !yield(i, &sctpData) {
					return
				}
				payload = sctpData.LayerPayload()
			case layers.SCTPChunkTypeInit, layers.SCTPChunkTypeInitAck:
				var sctpInit layers.SCTPInit
				if err := sctpInit.DecodeFromBytes(payload, failure); err != nil {
					failure.err = err
					yield(i, failure)
					return
				}
				if !yield(i, &sctpInit) {
					return
				}
				payload = sctpInit.LayerPayload()
			case layers.SCTPChunkTypeSack:
				var sctpSack layers.SCTPSack
				if err := sctpSack.DecodeFromBytes(payload, failure); err != nil {
					failure.err = err
					yield(i, failure)
					return
				}
				if !yield(i, &sctpSack) {
					return
				}
				payload = sctpSack.LayerPayload()
			case layers.SCTPChunkTypeHeartbeat, layers.SCTPChunkTypeHeartbeatAck:
				var sctpHeartbeat layers.SCTPHeartbeat
				if err := sctpHeartbeat.DecodeFromBytes(payload, failure); err != nil {
					failure.err = err
					yield(i, failure)
					return
				}
				if !yield(i, &sctpHeartbeat) {
					return
				}
				payload = sctpHeartbeat.LayerPayload()
			case layers.SCTPChunkTypeAbort, layers.SCTPChunkTypeError:
				var sctpError layers.SCTPError
				if err := sctpError.DecodeFromBytes(payload, failure); err != nil {
					failure.err = err
					yield(i, failure)
					return
				}
				if !yield(i, &sctpError) {
					return
				}
				payload = sctpError.LayerPayload()
			case layers.SCTPChunkTypeShutdown:
				var sctpShutdown layers.SCTPShutdown
				if err := sctpShutdown.DecodeFromBytes(payload, failure); err != nil {
					failure.err = err
					yield(i, failure)
					return
				}
				if !yield(i, &sctpShutdown) {
					return
				}
				payload = sctpShutdown.LayerPayload()
			case layers.SCTPChunkTypeShutdownAck:
				var sctpShutdownAck layers.SCTPShutdownAck
				if err := sctpShutdownAck.DecodeFromBytes(payload, failure); err != nil {
					failure.err = err
					yield(i, failure)
					return
				}
				if !yield(i, &sctpShutdownAck) {
					return
				}
				payload = sctpShutdownAck.LayerPayload()
			case layers.SCTPChunkTypeCookieEcho:
				var sctpCookieEcho layers.SCTPCookieEcho
				if err := sctpCookieEcho.DecodeFromBytes(payload, failure); err != nil {
					failure.err = err
					yield(i, failure)
					return
				}
				if !yield(i, &sctpCookieEcho) {
					return
				}
				payload = sctpCookieEcho.LayerPayload()
			case layers.SCTPChunkTypeCookieAck, layers.SCTPChunkTypeShutdownComplete:
				var sctpEmptyLayer layers.SCTPEmptyLayer
				if err := sctpEmptyLayer.DecodeFromBytes(payload, failure); err != nil {
					failure.err = err
					yield(i, failure)
					return
				}
				if !yield(i, &sctpEmptyLayer) {
					return
				}
				payload = sctpEmptyLayer.LayerPayload()
			default:
				var sctpUnknownChunkType layers.SCTPUnknownChunkType
				if err := sctpUnknownChunkType.DecodeFromBytes(payload, failure); err != nil {
					failure.err = err
					yield(i, failure)
					return
				}
				if !yield(i, &sctpUnknownChunkType) {
					return
				}
				payload = sctpUnknownChunkType.LayerPayload()
			}
		}
	}
}

// DecodeChunkFailure is a packet layer created if decoding of a specific SCTP
// chunk from bytes failed for some reason.
//
// It implements gopacket.ErrorLayer. LayerContents will be the entire set of
// bytes that failed to parse, and Error will return the reason parsing failed.
type DecodeChunkFailure struct {
	data      []byte
	err       error
	truncated bool
}

// Error returns the error encountered during decoding.
func (d *DecodeChunkFailure) Error() error { return d.err }

// LayerContents implements Layer.
func (d *DecodeChunkFailure) LayerContents() []byte { return d.data }

// LayerPayload implements Layer.
func (d *DecodeChunkFailure) LayerPayload() []byte { return nil }

// String implements fmt.Stringer.
func (d *DecodeChunkFailure) String() string {
	return fmt.Sprintf("decoding SCTP chunk from bytes: %v (truncated=%v)", d.err, d.truncated)
}

// LayerType returns gopacket.LayerTypeDecodeFailure because this is the
// layer-type that is returned when failing to decode a chunk in the classic
// Decoder API.
func (d *DecodeChunkFailure) LayerType() gopacket.LayerType {
	return gopacket.LayerTypeDecodeFailure
}

// SetTruncated implements gopacket.DecodeFeedback.
func (d *DecodeChunkFailure) SetTruncated() {
	d.truncated = true
}

// Truncated returns true if the chunk that failed to decode is truncated, which
// may contribute to its decoding failure.
func (d *DecodeChunkFailure) Truncated() bool {
	return d.truncated
}
