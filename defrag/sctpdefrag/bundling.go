package sctpdefrag

import (
	"strconv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func ChunksFrom(payload []byte) func(yield func(i int, chunk gopacket.Layer) bool) {
	return func(yield func(i int, chunk gopacket.Layer) bool) {
		// Predefining the variables to avoid dynamic allocations inside the loop.
		var (
			sctpData             layers.SCTPData
			sctpInit             layers.SCTPInit
			sctpSack             layers.SCTPSack
			sctpHeartbeat        layers.SCTPHeartbeat
			sctpError            layers.SCTPError
			sctpShutdown         layers.SCTPShutdown
			sctpShutdownAck      layers.SCTPShutdownAck
			sctpCookieEcho       layers.SCTPCookieEcho
			sctpEmptyLayer       layers.SCTPEmptyLayer
			sctpUnknownChunkType layers.SCTPUnknownChunkType
		)
		for i := 0; len(payload) != 0; i++ {
			failure := &DecodeChunkFailure{data: payload}
			chunkType := layers.SCTPChunkType(payload[0])
			switch chunkType {
			case layers.SCTPChunkTypeData:
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
	return "decoding SCTP chunk from bytes: " + d.Error().Error()
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

// SCTPChunkSkipper is an intermediate decoding layer that provides selective
// chunk processing by decoding and discarding chunks of unwanted types. The zero
// value skips all standard chunk types.
//
// This layer is particularly useful for efficiently processing large SCTP
// streams when you want to filter out specific chunk types, avoiding the overhead of
// decoding unwanted chunks.
//
// When a DecodingLayerContainer is Put multiple DecodingLayers for the same
// LayerType (i.e. their CanDecode functions overlap), the latter call to Put
// overwrites the previous call.
type SCTPChunkSkipper struct {
	// Excluded chunk types are attributed to other DecodingLayers (via the Payload
	// layer type). All other chunk types (i.e. chunk types not in this set) are
	// consumed and discarded by this DecodingLayer.
	excluded map[gopacket.LayerType]struct{}
	next     []byte // Stores the unprocessed portion of the decoded data for further layer processing.
}

// DiscardSCTPChunksExcept creates a chunk filter that skips (i.e. decodes and
// discards) all but the specified chunk types. The given chunk types are
// excluded by the returned DecodingLayer. This enables efficient processing of
// large SCTP streams when you want to filter out specific unwanted chunks.
//
// Examples:
//
//	// Discard/skip SACK chunks to focus on data processing.
//	DecodingLayerParser.AddDecodingLayer(DiscardSCTPChunksExcept(SCTPChunkTypeSack))
//
//	// Discard/skip heartbeat-related chunks.
//	DecodingLayerParser.AddDecodingLayer(DiscardSCTPChunksExcept(SCTPChunkTypeHeartbeat, SCTPChunkTypeHeartbeatAck))
//
//	// Discard/skip custom/proprietary chunk types.
//	DecodingLayerParser.AddDecodingLayer(DiscardSCTPChunksExcept(SCTPChunkType(200), SCTPChunkType(201)))
//
// To discard chunks with unknown types, use an arbitrary SCTPUnknownChunkType
// explicitly.
func DiscardSCTPChunksExcept(excluded ...layers.SCTPChunkType) *SCTPChunkSkipper {
	skipper := new(SCTPChunkSkipper)
	skipper.Exclude(excluded...)
	return skipper
}

// Exclude the given chunk-types from the set of chunk-types that will be skipped
// during decoding.
//
// Chunk types outside the predefined set of the IETF specification (those that
// aren’t part of LayerClassSCTPChunk) panic.
func (s *SCTPChunkSkipper) Exclude(excluded ...layers.SCTPChunkType) {
	// Zero-value initialisation means deferring the map's initialisation.
	if s.excluded == nil {
		s.excluded = make(map[gopacket.LayerType]struct{})
	}
	for _, chunkType := range excluded {
		chunkLayer := chunkType.LayerType()
		if chunkLayer == gopacket.LayerTypeZero {
			panic("SCTPChunkSkipper: Exclude called with an undefined chunk type " + strconv.Itoa(int(chunkType)))
		}
		if !layers.LayerClassSCTPChunk.Contains(chunkLayer) {
			panic("SCTPChunkSkipper: Exclude called with an non-standard chunk layer " + strconv.Itoa(int(chunkType)))
		}
		s.excluded[chunkLayer] = struct{}{}
	}
}

// DecodeFromBytes decodes the common SCTP chunk header to discard the portion of
// the data that encodes this chunk.
//
// This function is only called on chunks that should be discarded, as determined
// by SCTPChunkSelector.NextLayerType() and SCTPChunkSkipper.CanDecode.
func (s *SCTPChunkSkipper) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	var header layers.SCTPChunk
	err := header.DecodeFromBytes(data, df)
	if err != nil {
		return err
	}
	// Skip this chunk entirely and return data starting from the next chunk.
	s.next = data[header.ActualLength:]
	return nil
}

// CanDecode returns a dynamic LayerClass containing the LayerTypes corresponding
// to chunk types that should be consumed (and discarded) by this DecodingLayer.
// This includes all standard SCTP chunk types (LayerClassSCTPChunk), except for
// LayerTypeSCTPUnknownChunkType and those explicitly excluded by prior calls to
// Exclude.
//
// The returned LayerClass enables the DecodingLayerParser to route chunks
// correctly: chunks with types in the excluded set are processed normally, while
// all other chunks are skipped entirely (consumed and discarded).
//
// Unlike most DecodingLayers that return a fixed LayerClass, SCTPChunkSkipper's
// CanDecode adapts dynamically as chunk types are excluded via Exclude().
//
// This function is only called when the SCTPChunkSkipper is Put into a
// DecodingLayerContainer, so it doesn't affect the performance-critical
// code-path.
func (s *SCTPChunkSkipper) CanDecode() gopacket.LayerClass {
	// The LayerTypes of SCTP chunk layers are defined in two locations:
	// LayerClassSCTPChunk and SCTPChunkTypeMetadata.
	//
	// The former includes the layer-type of a layer that decodes any chunk (useful
	// for unknown chunk types), but unknown chunk types are not part of the scope of
	// this DecodingLayer.
	//
	// The latter is used by users to extend the set of known chunk types. It maps
	// each non-standard chunk type to a layer-type (or the zero-layer if undefined),
	// in addition to the standard chunk types.
	var skipped []gopacket.LayerType
	for _, l := range layers.LayerClassSCTPChunk.LayerTypes() {
		// The SCTPUnknownChunkType layer can decode chunks with unknown types, but we
		// are not interested in skipping those within the context of this DecodingLayer.
		if l == layers.LayerTypeSCTPUnknownChunkType {
			continue
		}
		// Explicitly excluded layer types are not decodable by this DecodingLayer,
		// allowing the DecodingLayerContainer to provide other DecodingLayers for them.
		if _, ok := s.excluded[l]; ok {
			continue
		}
		// All remaining chunk types should be consumed and discarded by this DecodingLayer.
		skipped = append(skipped, l)
	}
	return gopacket.NewLayerClass(skipped)
}

// NextLayerType always returns gopacket.LayerTypePayload, behaving like
// SCTP.NextLayerType.
//
// In most cases, the Payload layer type triggers an SCTPChunkSelector to guide
// the appropriate decoding for the next chunk.
//
// This function is only called on chunks that should be discarded, as determined
// by SCTPChunkSelector.NextLayerType() and SCTPChunkSkipper.CanDecode.
func (s *SCTPChunkSkipper) NextLayerType() gopacket.LayerType {
	// The decoded chunk type was discarded, move on to the next chunk.
	return gopacket.LayerTypePayload
}

// LayerPayload returns the remaining bytes to be decoded by the next layer.
//
// This function is only called on chunks that should be discarded, as determined
// by SCTPChunkSelector.NextLayerType() and SCTPChunkSkipper.CanDecode.
func (s *SCTPChunkSkipper) LayerPayload() []byte {
	return s.next
}
