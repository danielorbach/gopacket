package sctpdefrag

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ChunkBundle implements a decoding layer used to handle various SCTP chunk
// types in a packet. A zero ChunkBundle is invalid.
//
// The layer-type on an invalid ChunkBundle is the zero layer-type. Likewise,
// other getters return appropriate zero values.
type ChunkBundle struct {
	chunkType   layers.SCTPChunkType
	data        layers.SCTPData
	init        layers.SCTPInit
	sack        layers.SCTPSack
	heartbeat   layers.SCTPHeartbeat
	error       layers.SCTPError
	shutdown    layers.SCTPShutdown
	shutdownAck layers.SCTPShutdownAck
	cookie      layers.SCTPCookieEcho
	empty       layers.SCTPEmptyLayer
	unknown     layers.SCTPUnknownChunkType

	// The portion of the entire SCTP PDU that has been decoded (i.e. a single
	// chunk).
	content []byte
	// Remaining portion of the SCTP PDU to decode.
	next []byte
	// Indicates whether the decoding layer is in a valid state after decoding. We
	// maintain this value because some methods are "undefined" before decoding a
	// chunk.
	valid bool
}

// DecodeFromBytes decodes the provided bytes into this layer. Upon successful
// decoding, the layer is marked as valid, and the next bytes to decode are
// calculated based on the chunk length. Otherwise, it returns a non-nil error.
//
// After successful decoding, call Header() and Layer() to access the decoded
// chunk.
func (l *ChunkBundle) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	// Failing to decode from bytes leaves the layer in an invalid state.
	l.valid = false
	if len(data) == 0 {
		return fmt.Errorf("no data to decode")
	}
	err := l.decodeChunk(data, df)
	if err != nil {
		return err
	}
	l.valid = true

	// Upon successfully decoding a chunk, its header contains the length of the
	// entire chunk, counting the header and any additional payload (e.g. the
	// UserData of DATA chunks).
	//
	// However, this length does not take padding into account. Padding bytes are
	// part of the SCTP PDU, ensuring chunks always align to 4-byte boundaries.
	length := roundUpToNearest4(l.Header().Length)
	// Alas, the packet may be truncated, so we must check if the data contains
	// length bytes indeed. Since we have already decoded the chunk successfully, we
	// set truncated but return a nil error.
	if len(data) < int(length) {
		df.SetTruncated()
		l.next = nil
		return nil
	}
	l.content = data[:l.Header().Length]
	l.next = data[length:]
	return nil
}

func (l *ChunkBundle) decodeChunk(data []byte, df gopacket.DecodeFeedback) error {
	l.chunkType = layers.SCTPChunkType(data[0])
	switch l.chunkType {
	case layers.SCTPChunkTypeData:
		return l.data.DecodeFromBytes(data, df)
	case layers.SCTPChunkTypeInit, layers.SCTPChunkTypeInitAck:
		return l.init.DecodeFromBytes(data, df)
	case layers.SCTPChunkTypeSack:
		return l.sack.DecodeFromBytes(data, df)
	case layers.SCTPChunkTypeHeartbeat, layers.SCTPChunkTypeHeartbeatAck:
		return l.heartbeat.DecodeFromBytes(data, df)
	case layers.SCTPChunkTypeAbort, layers.SCTPChunkTypeError:
		return l.error.DecodeFromBytes(data, df)
	case layers.SCTPChunkTypeShutdown:
		return l.shutdown.DecodeFromBytes(data, df)
	case layers.SCTPChunkTypeShutdownAck:
		return l.shutdownAck.DecodeFromBytes(data, df)
	case layers.SCTPChunkTypeCookieEcho:
		return l.cookie.DecodeFromBytes(data, df)
	case layers.SCTPChunkTypeCookieAck, layers.SCTPChunkTypeShutdownComplete:
		return l.empty.DecodeFromBytes(data, df)
	default:
		return l.unknown.DecodeFromBytes(data, df)
	}
}

func roundUpToNearest4(i uint16) uint16 {
	if i%4 == 0 {
		return i
	}
	return i + 4 - (i % 4)
}

// Header returns the SCTPChunk header of the currently decoded chunk.
//
// If the layer is not in a valid state, an empty SCTPChunk is returned.
func (l *ChunkBundle) Header() layers.SCTPChunk {
	if !l.valid {
		return layers.SCTPChunk{}
	}
	switch l.chunkType {
	case layers.SCTPChunkTypeData:
		return l.data.SCTPChunk
	case layers.SCTPChunkTypeInit, layers.SCTPChunkTypeInitAck:
		return l.init.SCTPChunk
	case layers.SCTPChunkTypeSack:
		return l.sack.SCTPChunk
	case layers.SCTPChunkTypeHeartbeat, layers.SCTPChunkTypeHeartbeatAck:
		return l.heartbeat.SCTPChunk
	case layers.SCTPChunkTypeAbort, layers.SCTPChunkTypeError:
		return l.error.SCTPChunk
	case layers.SCTPChunkTypeShutdown:
		return l.shutdown.SCTPChunk
	case layers.SCTPChunkTypeShutdownAck:
		return l.shutdownAck.SCTPChunk
	case layers.SCTPChunkTypeCookieEcho:
		return l.cookie.SCTPChunk
	case layers.SCTPChunkTypeCookieAck, layers.SCTPChunkTypeShutdownComplete:
		return l.empty.SCTPChunk
	default:
		return l.unknown.SCTPChunk
	}
}

// Layer checks whether the currently decoded chunk matches the specified layer
// type. It returns the decoded chunk layer if it matches, or nil if it does not.
func (l *ChunkBundle) Layer(layerType gopacket.LayerType) gopacket.Layer {
	if !l.valid {
		return nil
	}
	c := l.chunkLayer()
	if c.LayerType() == layerType {
		return c
	}
	return nil
}

// Only call this function on a valid ChunkBundle. Otherwise, the function
// returns nil.
func (l *ChunkBundle) chunkLayer() gopacket.Layer {
	if !l.valid {
		// We return nil explicitly instead of relying on callers to check this field
		// before calling this method. This approach is more likely to panic as a result
		// of developer oversight.
		return nil
	}
	switch l.chunkType {
	case layers.SCTPChunkTypeData:
		return &l.data
	case layers.SCTPChunkTypeInit, layers.SCTPChunkTypeInitAck:
		return &l.init
	case layers.SCTPChunkTypeSack:
		return &l.sack
	case layers.SCTPChunkTypeHeartbeat, layers.SCTPChunkTypeHeartbeatAck:
		return &l.heartbeat
	case layers.SCTPChunkTypeAbort, layers.SCTPChunkTypeError:
		return &l.error
	case layers.SCTPChunkTypeShutdown:
		return &l.shutdown
	case layers.SCTPChunkTypeShutdownAck:
		return &l.shutdownAck
	case layers.SCTPChunkTypeCookieEcho:
		return &l.cookie
	case layers.SCTPChunkTypeCookieAck, layers.SCTPChunkTypeShutdownComplete:
		return &l.empty
	default:
		return &l.unknown
	}
}

// CanDecode returns the LayerClass this DecodingLayer decodes. which is
// [layers.LayerClassSCTPChunk], indicating it can decode SCTP chunks.
func (l *ChunkBundle) CanDecode() gopacket.LayerClass {
	return layers.LayerClassSCTPChunk
}

// NextLayerType always returns gopacket.LayerTypeZero because SCTP chunks are
// not expected to contain other layers within them.
//
// Data chunks carry user-data, though a single application layer may be
// fragmented into multiple DATA chunks. Use the defragmentation mechanisms
// provided by this package to reconstruct the original user-data and access the
// encapsulated layer.
//
// The other chunk types do not carry any user-data.
func (l *ChunkBundle) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypeZero
}

// LayerPayload returns the remaining bytes of the SCTP PDU, following the last
// decoded chunk. It returns nil if the layer is not in a valid state.
func (l *ChunkBundle) LayerPayload() []byte {
	if !l.valid {
		return nil
	}
	return l.next
}

// LayerType returns the gopacket.LayerType of the current chunk layer, or
// [gopacket.LayerTypeZero] if the layer is not in a valid state.
func (l *ChunkBundle) LayerType() gopacket.LayerType {
	if !l.valid {
		return gopacket.LayerTypeZero
	}
	return l.chunkLayer().LayerType()
}

// LayerContents returns the bytes that make up this layer, or nil of the layer
// is not in a valid state.
func (l *ChunkBundle) LayerContents() []byte {
	if !l.valid {
		return nil
	}
	return l.content
}
