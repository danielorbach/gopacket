package sctpdefrag

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"sort"
	"strconv"
	"strings"
)

// Defragmenter reassembles SCTP DATA chunks that have been fragmented.
// SCTP allows messages to be split across multiple DATA chunks using
// BeginFragment and EndFragment flags.
//
// TODO: explain a defragmented per association & direction.
// TODO: support a NoCopy option for better performance in appropriate scenarios.
type Defragmenter struct {
	// Maps stream identifier and sequence number to a list of fragments.
	reassembly map[messageKey]*messageContext
}

// TODO: expose statistics (processed chunks, reassembled chunks, invalid chunks, invalid internal states, etc).

// TODO: optimise with memory pool because all non-last fragments are the same size (controlled by the PMTU).

// TODO: support message fragments out of order (e.g. [1,3,2] or [3,2,1]).

// NewDefragmenter creates a new SCTP DATA chunk defragmenter.
func NewDefragmenter() *Defragmenter {
	return &Defragmenter{
		reassembly: make(map[messageKey]*messageContext),
	}
}

// DefragData takes in a DATA chunk with a possibly fragmented payload, and
// returns either:
//
//   - a ready-to-be-used [layers.SCTPData] layer, if the chunk is fully
//     defragmented.
//   - a nil layer, if the chunk is still fragmented.
//   - an error, if the chunk is invalid.
//
// It doesn't modify the given chunk layer in place, so 'data' remains untouched.
//
// If the passed-in message is NOT fragmented, it will immediately return the
// chunk, without modifying the layer.
//
// If the message is fragmented, and we don't have all fragments (yet), it will
// return nil and store whatever internal information it needs to eventually
// defragment the message.
//
// If the chunk layer contains the last fragment needed to reconstruct the
// message, a new [layers.SCTPData] layer will be returned and will be set to the
// entire defragmented message.
//
// It uses a map of all the running streams.
//
// The function expects to be called in the order of the chunks (by TSN).
// Nonetheless, the implementation is preparing to support out-of-order
// fragments, so the middle chunks (i.e. neither the first nor the last) may be
// processed in any order.
//
// Processing chunks in any order is useful when the observed traffic contains
// retransmissions (e.g. due to selective acknowledgements with gaps).
func (d *Defragmenter) DefragData(data *layers.SCTPData) (complete *layers.SCTPData, err error) {
	// Immediately return if the chunk is invalid for defragmentation.
	if err := checkDataChunk(data); err != nil {
		return nil, fmt.Errorf("invalid chunk: %w", err)
	}

	// Shortcut for whole messages that are not fragmented - return immediately.
	if data.BeginFragment && data.EndFragment {
		return data, nil
	}

	key := messageKeyOf(data)

	// All messages begin with the first fragment.
	if data.BeginFragment {
		if _, ok := d.reassembly[key]; ok {
			// We already have this message pending, so we don't need to do anything.
			return nil, fmt.Errorf("message already pending: %v", key)
		}
		d.reassembly[key] = beginMessageReassembly(data)
		return nil, nil
	}

	// By this point in the code, we know that the message is fragmented, and we
	// expect to have already processed its first fragment.
	reassembly, ok := d.reassembly[key]
	if !ok {
		return nil, fmt.Errorf("no pending message: %v", key)
	}

	// All messages end with the last fragment.
	if data.EndFragment {
		reassembly.append(data)
		reassembled, err := reassembly.reassemble()
		if err != nil {
			return nil, fmt.Errorf("reassemble: %w", err)
		}
		delete(d.reassembly, key)
		return reassembled, nil
	}

	// If we get here, we have a fragment that is neither the first nor the last.
	reassembly.append(data)
	return nil, nil
}

func checkDataChunk(data *layers.SCTPData) error {
	// We only support DATA chunks.
	if data.Type != layers.SCTPChunkTypeData {
		return fmt.Errorf("unsupported chunk type %q", data.Type)
	}
	// DATA chunks always have 16 bytes of header.
	if data.ActualLength != 16 {
		return fmt.Errorf("malformed chunk header")
	}
	// The Length field references the payload and the header, without padding.
	length := data.ActualLength + len(data.Payload)
	if int(data.Length) != length {
		return fmt.Errorf("payload length mismatch")
	}
	return nil
}

type messageKey struct {
	// A Stream Identifier contains an ordered sequence of messages.
	SID uint16
	// A Stream Sequence Number is a monotonically increasing counter used to
	// identify the order of messages within a stream.
	SSN uint16
}

func (m messageKey) String() string {
	return fmt.Sprintf("SID=%v, SSN=%v", m.SID, m.SSN)
}

// MakeMessageKey creates a unique key for a stream ID and sequence number
func messageKeyOf(data *layers.SCTPData) messageKey {
	return messageKey{SID: data.StreamId, SSN: data.StreamSequence}
}

// A messageContext tracks the fragments of a specific message in a stream.
//
// The term "stream" is used in SCTP to refer to a sequence of user messages that
// are to be delivered to the upper-layer protocol IN ORDER with respect to other
// messages within the same stream.
//
// All exported fields stored in this struct MUST have the same value for all
// fragments of the same message.
type messageContext struct {
	// SCTP provides a mechanism for bypassing the sequenced delivery service. User
	// messages marked as Unordered are delivered to the SCTP user as soon as they’re
	// received.
	//
	// If an unordered user message is fragmented, each fragment of the message MUST
	// have its U bit set to 1.
	//
	// Since we’re passively observing traffic, this is meaningless for our purposes,
	// but we track this field nonetheless.
	Unordered bool
	// Identifies the stream to which the following user data belongs.
	StreamId uint16
	// This value represents the Stream Sequence Number of the following user data
	// within the stream.
	//
	// When SCTP fragments a user message for transport, the same Stream Sequence
	// Number MUST be carried in each fragment of the message.
	StreamSequence uint16
	// This field MUST be sent even in fragmented DATA chunks (to make sure it is
	// available for agents in the middle of the network).
	PayloadProtocol layers.SCTPPayloadProtocol

	// Fragments is a collection of fragments representing all tracked portions of a
	// user message within a stream
	fragments []fragment
}

// BeginMessageReassembly initialises a message reassembly context for a new
// message.
//
// It should be called once, with the first fragment of the message. The first
// fragment is identified by the [layers.SCTPData.BeginFragment] flag.
func beginMessageReassembly(data *layers.SCTPData) *messageContext {
	// We've never seen a message fragmented over more than 3 SCTP packets, yet 4
	// seems like a rounder number.
	const commonFragmentation = 4
	m := &messageContext{
		Unordered:       data.Unordered,
		StreamId:        data.StreamId,
		StreamSequence:  data.StreamSequence,
		PayloadProtocol: data.PayloadProtocol,
		fragments:       make([]fragment, 0, commonFragmentation),
	}
	m.append(data)
	return m
}

// Append stores a piece of a fragmented user message such that it can be
// reassembled later.
//
// It copies the payload from the layer because packets may become invalid by the
// time the next chunk is processed.
func (m *messageContext) append(data *layers.SCTPData) {
	// We use the Length field, instead of len(data.Payload), because the latter
	// includes padding (to a 4-byte boundary). While the former includes the chunk's
	// header, this can be overcome by subtracting data.ActualLength (always 16
	// bytes).
	length := int(data.Length) - data.ActualLength
	// We must copy the user data from the layer to ensure that it remains valid
	// until we reassemble the message.
	userData := make([]byte, length)
	copy(userData, data.Payload) // Copies without the padding.
	m.fragments = append(m.fragments, fragment{
		TSN:           data.TSN,
		UserData:      userData,
		BeginFragment: data.BeginFragment,
		EndFragment:   data.EndFragment,
	})
}

var (
	errMissingFragments     = errors.New("fragments are not strictly sequential")
	errMissingBeginFragment = errors.New("missing first fragment")
	errMissingEndFragment   = errors.New("missing last fragment")
)

// Reassemble constructs a synthetic DATA chunk from the fragments of a user message.
//
// The returned chunk will have the following unique properties:
//   - The TSN field will be set to 0.
//   - The Content field is ni. Serialise the returned SCTPData to compute it.
//   - The BeginFragment and EndFragment flags are set.
func (m *messageContext) reassemble() (*layers.SCTPData, error) {
	// First, we sum up the total length of all fragments to allocate the correct
	// amount of memory for the payload, once.
	var size int
	for _, frag := range m.fragments {
		size += len(frag.UserData)
	}

	// We may have observed fragments out-of-order, so we must sort them by TSN
	// before reassembling them.
	sort.Slice(m.fragments, func(i, j int) bool {
		return m.fragments[i].TSN < m.fragments[j].TSN
	})
	// We also want to ensure that the fragments are indeed strictly sequential, as
	// the RFC mandates. Though ordered, the TSN values are not necessarily
	// consecutive. For example, we may have missed a fragment, but still called this
	// function.
	for i := 1; i < len(m.fragments); i++ {
		step := m.fragments[i].TSN - m.fragments[i-1].TSN
		if step != 1 {
			return nil, errMissingFragments
		}
	}
	// We also want to ensure that the first fragment is indeed the first fragment,
	// and that the last fragment is indeed the last fragment.
	if !m.fragments[0].BeginFragment {
		return nil, errMissingBeginFragment
	}
	if !m.fragments[len(m.fragments)-1].EndFragment {
		return nil, errMissingEndFragment
	}

	// Then, we can allocate the payload buffer and COPY all fragments into it.
	var payload bytes.Buffer
	payload.Grow(size)
	for _, frag := range m.fragments {
		payload.Write(frag.UserData)
	}

	// We must round the length to the nearest 4-byte boundary, as the RFC mandates.
	// Nonetheless, we don't pad the payload, in accordance with the SCTPData layer.
	var padding int
	if payload.Len()%4 != 0 {
		padding = 4 - (payload.Len() % 4)
	}

	// The Flags field is composed of three flags: U, B, and E. While B and E are
	// always on for whole messages, U is only on if the Unordered field is set.
	var flags uint8 = 0b0011 // B and E are always on.
	if m.Unordered {
		flags |= 0b0100 // U is on if the Unordered field is set.
	}

	//Finally, we can create a synthetic chunk with the reassembled payload.
	return &layers.SCTPData{
		SCTPChunk: layers.SCTPChunk{
			BaseLayer: layers.BaseLayer{
				Contents: nil,
				Payload:  payload.Bytes(),
			},
			Type:  layers.SCTPChunkTypeData,
			Flags: flags,
			// This field indicates the length of the DATA chunk in bytes from the beginning
			// of the type field to the end of the User Data field, excluding any padding. A
			// DATA chunk with a User Data field of length L will have the Length field set
			// to (16 + L) (indicating 16 + L bytes) where L MUST be greater than 0.
			Length:       uint16(16 + payload.Len() + padding),
			ActualLength: 16, // DATA chunks are always 16 bytes long.
		},
		Unordered:       m.Unordered, // Preserve the Unordered flag.
		BeginFragment:   true,        // Reassembled chunks always have the first bytes of a message.
		EndFragment:     true,        // Reassembled chunks always have the last bytes of a message.
		TSN:             0,
		StreamId:        m.StreamId,
		StreamSequence:  m.StreamSequence,
		PayloadProtocol: m.PayloadProtocol,
	}, nil
}

// A fragment holds a portion of a user message.
//
// When a user message is fragmented into multiple chunks, the messageContext
// uses the TSN field to reassemble the message. The TSNs for each fragment of a
// fragmented user message are strictly sequential.
type fragment struct {
	// This value represents the TSN for the DATA chunk carrying this fragment.
	TSN uint32
	// This is the payload user data.
	//
	// Note that implementations MUST pad the end of the data to a 4-byte boundary
	// with all zero bytes. Any padding isn't included in the Length field of the
	// DATA chunk.
	UserData []byte

	// BeginFragment indicates whether this fragment is the first chunk of the
	// fragmented message.
	BeginFragment bool
	// EndFragment indicates whether this fragment is the last chunk of the
	// fragmented message.
	EndFragment bool
}

func (f fragment) String() string {
	var position string
	if f.BeginFragment {
		position = "first"
	} else if f.EndFragment {
		position = "last"
	} else {
		position = "middle"
	}
	return fmt.Sprintf("UseData=%v bytes, TSN=%v, Position=%v", len(f.UserData), f.TSN, position)
}

func (f fragment) GoString() string {
	var b strings.Builder
	b.WriteString("SCTPFragment{")
	b.WriteString("TSN: " + strconv.Itoa(int(f.TSN)))
	b.WriteString(", UserData: " + gopacket.LongBytesGoString(f.UserData))
	if f.BeginFragment {
		b.WriteString(", BeginFragment: true")
	}
	if f.EndFragment {
		b.WriteString(", EndFragment: true")
	}
	b.WriteString("}")
	return b.String()
}
