package sctpdefrag

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

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
