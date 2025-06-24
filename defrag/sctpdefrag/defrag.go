package sctpdefrag

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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

// TODO: document package.

// TODO: purge the reassembly map of contexts that are no longer needed (by association).

// TODO: expose statistics (processed chunks, reassembled chunks, invalid chunks, invalid internal states, etc).

// TODO: optimise with memory pool because all non-last fragments are the same size (controlled by the PMTU).

// NewDefragmenter creates a new SCTP DATA chunk defragmenter.
func NewDefragmenter() *Defragmenter {
	return &Defragmenter{
		reassembly: make(map[messageKey]*messageContext),
	}
}

// DefragData takes in a DATA chunk with a possibly fragmented payload and
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
func (d *Defragmenter) DefragData(assoc Association, data *layers.SCTPData) (complete *layers.SCTPData, err error) {
	key := messageKeyOf(assoc, data)

	// Immediately return if the chunk is invalid for defragmentation.
	if err := checkDataChunk(data); err != nil {
		return nil, fmt.Errorf("invalid chunk: %w", err)
	}

	// Shortcut for whole messages that are not fragmented - return immediately.
	if data.BeginFragment && data.EndFragment {
		return data, nil
	}

	// The first packet we encounter for a specific sequence, of a specific stream,
	// in a specific association, isn't necessarily the first fragment of the
	// message.
	context, ok := d.reassembly[key]
	if !ok {
		// Note that beginMessageReassembly does not Push the data chunk into the
		// messageContext.
		context = beginMessageReassembly(data)
		d.reassembly[key] = context
	}

	more, err := context.Push(data)
	if err != nil {
		return nil, fmt.Errorf("push fragment: %w", err)
	}
	if more {
		// If we get here, the message is still incomplete and waiting for more
		// fragments, so we return nil.
		return nil, nil
	}

	// If we get here, the message appears to be complete, so we attempt to
	// reassemble it. If it is not indeed complete, the reassembly will fail now and
	// continue to fail indefinitely for this context.
	reassembled, err := context.Reassemble()
	if err != nil {
		// Delete the context from the reassembly map, as it will remain in an invalid
		// state even after future fragments are processed.
		delete(d.reassembly, key)
		return nil, fmt.Errorf("reassemble: %w", err)
	}
	delete(d.reassembly, key)
	return reassembled, nil
}

func checkDataChunk(data *layers.SCTPData) error {
	// We only support DATA chunks.
	if data.Type != layers.SCTPChunkTypeData {
		return fmt.Errorf("unexpected chunk type %q", data.Type)
	}
	// A DATA chunk has at least 1 byte of payload.
	if data.ActualLength <= 16 {
		return fmt.Errorf("malformed chunk header: DATA chunks requires more than %v bytes", data.ActualLength)
	}
	// A DATA chunk's actual length includes the padding, if any. As such, it cannot
	// be less than the Length field, which excludes any padding.
	if data.ActualLength < int(data.Length) {
		return fmt.Errorf("malformed chunk header: unexpected chunk lengths (padded=%v, unpadded=%v)", data.ActualLength, data.Length)
	}
	// The Length field includes the common chunk header and its type-specific
	// content, excluding any padding. The common chunk header and DATA-specific
	// fields occupy the first 16 bytes of the chunk. The user-supplied data payload
	// immediately follows.
	length := int(data.Length) - 16
	if len(data.UserData) != length {
		return fmt.Errorf("truncated user data: payload with %v out of %v bytes", len(data.UserData), length)
	}
	return nil
}

// A messageKey uniquely identifies a fragmented message within an SCTP
// association.
type messageKey struct {
	// Identifies the SCTP association this message belongs to.
	Association
	// A Stream Identifier contains an ordered sequence of messages.
	SID uint16
	// A Stream Sequence Number is a monotonically increasing counter used to
	// identify the order of messages within a stream.
	SSN uint16
}

func (m messageKey) String() string {
	return fmt.Sprintf("ASSOC={%v} SID=%v, SSN=%v", m.Association, m.SID, m.SSN)
}

// MakeMessageKey creates a unique key for a stream ID and sequence number
func messageKeyOf(assoc Association, data *layers.SCTPData) messageKey {
	return messageKey{Association: assoc, SID: data.StreamId, SSN: data.StreamSequence}
}

// Association represents an SCTP association between two peers. It uniquely
// identifies a unidirectional communication channel between two participants.
//
// In SCTP (RFC 4960), an association is established between two peers and is
// defined by their transport endpoints (IP addresses and ports) and verification
// tags. While SCTP supports multi-homed peers (i.e. peers with multiple IP
// addresses), this implementation only supports single-endpoint peers. At any
// given time, there can only be one association in each direction between two
// peers. However, sequential associations can exist between the same peers over
// time, distinguished by their verification tags. This allows SCTP to handle
// association restarts, where a new association replaces an old one.
//
// The verification tag serves as an association identifier that remains constant
// for the life of the association. When a peer receives an SCTP packet, it uses
// the verification tag to determine which association the packet belongs to,
// preventing packets from old associations from being accepted by new ones.
type Association struct {
	// Addresses contain the source and destination IP addresses of the two SCTP
	// peers. In full SCTP, each peer could have multiple endpoints (addresses), but
	// this implementation tracks only a single endpoint per peer.
	Addresses gopacket.Flow
	// The source and destination SCTP ports used by the peers for this association.
	Ports gopacket.Flow
	// Like a session identifier, this tag is used to validate that packets belong to
	// this specific association instance, distinguishing it from any previous or
	// future associations between the same peers.
	VerificationTag uint32
}

// NewAssociation extracts the association identifier from the packet's network
// and SCTP layers.
//
// The Association uniquely identifies the unidirectional SCTP communication
// channel for all chunks carried by this packet.
func NewAssociation(ip gopacket.NetworkLayer, sctp *layers.SCTP) Association {
	return Association{
		Addresses:       ip.NetworkFlow(),
		Ports:           sctp.TransportFlow(),
		VerificationTag: sctp.VerificationTag,
	}
}

func (a Association) String() string {
	return fmt.Sprintf("Peers=%v:%v->%v:%v TAG=%v", a.Addresses.Src(), a.Ports.Src(), a.Addresses.Dst(), a.Ports.Dst(), a.VerificationTag)
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

	// A collection of fragments representing all tracked portions of a user message
	// within a stream.
	Fragments fragmentList
}

// BeginMessageReassembly initialises a message reassembly context for a new
// message.
//
// It should be called once, not necessarily with the first fragment of the
// message (identified by the [layers.SCTPData.BeginFragment] flag).
func beginMessageReassembly(data *layers.SCTPData) *messageContext {
	// We've never seen a message fragmented over more than 3 SCTP packets, yet 4
	// seems like a rounder number.
	//
	// DATA chunks with the complete message don't arrive at this function, so we
	// don't need to optimise for the most common case of non-fragmented messages.
	const commonFragmentation = 4
	m := &messageContext{
		Unordered:       data.Unordered,
		StreamId:        data.StreamId,
		StreamSequence:  data.StreamSequence,
		PayloadProtocol: data.PayloadProtocol,
		// We preallocate a slice of fragments to avoid reallocating memory on every
		// insert. The number is arbitrary, but we expect most messages to be small, so
		// we set it to a small number.
		Fragments: fragmentList{List: make([]fragment, 0, commonFragmentation)},
	}
	return m
}

// Push stores a piece of a fragmented user message such that it can be
// defragmented later into a reconstructed DATA chunk.
//
// It copies the payload from the layer because packets may become invalid by the
// time the next chunk is processed.
//
// The function returns true if more fragments are expected (i.e. the message is
// still incomplete), or false if the message appears complete and ready to be
// reassembled.
//
// Note, this function doesn't guarantee that the message is indeed complete or
// that reassembly will succeed indeed.
func (m *messageContext) Push(data *layers.SCTPData) (more bool, err error) {
	frag := copyFragment(data)
	if err := m.Fragments.Insert(frag); err != nil {
		return true, err
	}
	if !m.Fragments.BeginFragment {
		return true, nil
	}
	if !m.Fragments.EndFragment {
		return true, nil
	}
	// Consider two sequential fragments with TSNs A and B (A = B - 1), then the
	// delta between them is 1, but there are two fragments in the list.
	n := m.Fragments.deltaTSN(m.Fragments.EndTSN, m.Fragments.BeginTSN)
	if int(n)+1 != len(m.Fragments.List) {
		return true, nil
	}
	// If we get here, we seem to have all fragments of the message, so we can
	// attempt and reassemble it.
	return false, nil
}

var (
	errUserDataTooLong = errors.New("user data exceeds maximum length (65535 bytes)")
)

// Reassemble constructs a synthetic DATA chunk from the fragments of a user message.
//
// The returned chunk will have the following unique properties:
//   - The TSN field will be set to 0.
//   - The Content field is nil. Serialise the returned SCTPData to compute it.
//   - The BeginFragment and EndFragment flags are set.
func (m *messageContext) Reassemble() (*layers.SCTPData, error) {
	// First, we defragment the message by copying all fragments into a single byte
	// slice. This is the UserData field of the DATA chunk.
	userData := make([]byte, m.Fragments.TotalBytes())
	userDataLen, err := m.Fragments.Defragment(userData)
	if err != nil {
		return nil, fmt.Errorf("defragment user-data: %w", err)
	}
	userData = userData[:userDataLen] // Trim just in case, although we pre-allocated exactly the right size.

	// The length field of a DATA chunk with a UserData field of length L will have
	// the Length field set to (16 + L), indicating 16+L bytes, where L MUST be
	// greater than 0.
	length := 16 + userDataLen // Must be int to prevent uint16 overflows.
	// Though supported by SCTP, supporting messages larger than 64KB would require
	// more complexity from users. By upholding this limitation, we provide users
	// with familiar DATA chunks.
	if length > math.MaxUint16 {
		return nil, errUserDataTooLong
	}
	// The Length field does not include any padding, but a valid chunk is always
	// padded to a 4-byte boundary.
	actual := roundUpToNearest4(length)

	// The Flags field is composed of three flags: U, B, and E. While B and E are
	// always on for whole messages, U is only on if the Unordered field is set.
	var flags uint8 = 0b0011 // B and E are always on.
	if m.Unordered {
		flags |= 0b0100 // U is on if the Unordered field is set.
	}

	// Finally, we can create a synthetic chunk with the reassembled User Data payload.
	return &layers.SCTPData{
		SCTPChunk: layers.SCTPChunk{
			// Like most constructed layers, the BaseLayer is empty. This field is populated
			// when decoding a layer. It does not interfere with the serialisation of the
			// layer, as the SerializeTo method traditionally ignores the BaseLayer field.
			BaseLayer: layers.BaseLayer{},
			Type:      layers.SCTPChunkTypeData,
			Flags:     flags,
			// This field indicates the length of the DATA chunk in bytes from the beginning
			// of the type field to the end of the UserData field, excluding any padding.
			Length:       uint16(length), // Safely cast to uint16, as we checked earlier.
			ActualLength: actual,
		},
		Unordered:       m.Unordered, // Preserve the Unordered flag.
		BeginFragment:   true,        // Reassembled chunks always have the first bytes of a message.
		EndFragment:     true,        // Reassembled chunks always have the last bytes of a message.
		TSN:             0,           // Since this synthetic chunk spans several TSNs, we set it to 0.
		StreamId:        m.StreamId,
		StreamSequence:  m.StreamSequence,
		PayloadProtocol: m.PayloadProtocol,
		UserData:        userData,
	}, nil
}

func roundUpToNearest4(i int) int {
	if i%4 == 0 {
		return i
	}
	return i + 4 - (i % 4)
}

// A fragmentList holds a list used to contain SCTP fragments, which are
// extraction of DATA chunks.
//
// It stores internal counters to track the maximum total of bytes accumulated
// and the current length it has received. It also stores a flag to know if he
// has seen the last packet.
type fragmentList struct {
	List []fragment // A list of fragments that have been received so far.

	// Indicates whether the first fragment has been seen.
	//
	// TSN 0 is a valid TSN, so we can’t use it to determine if the first fragment
	// has been seen.
	BeginFragment bool
	BeginTSN      uint32 // The TSN of the first fragment, not necessarily the lowest TSN (due to TSN overflow).
	// Indicates whether the last fragment has been seen.
	//
	// TSN 0 is a valid TSN, so we can’t use it to determine if the last fragment
	// has been seen.
	EndFragment bool
	EndTSN      uint32 // The TSN of the last fragment, not necessarily the highest TSN (due to TSN overflow).
}

func (l *fragmentList) Insert(f fragment) error {
	// Retransmissions may occur, so we need to check if the fragment is already
	// present in the list. If it is, we can ignore it.
	//
	// We simply iterate over the list without optimisation, as the number of
	// fragments is expected to be small (most certainly single digits).
	for _, existing := range l.List {
		if f.TSN == existing.TSN {
			// If the fragment is already present, we ignore it without checking that it is
			// indeed the same as the existing one.
			return nil
		}
	}

	// The first fragment of a message is special because it is critical to correctly
	// ordering the other fragments, which is non-trivial due to TSN overflows.
	if f.BeginFragment {
		// If we've already seen the first fragment, we cannot insert another one unless
		// it is the same TSN (due to retransmissions).
		if l.BeginFragment {
			if f.TSN != l.BeginTSN {
				return fmt.Errorf("message already began with TSN %v", l.BeginTSN)
			}
			// If the TSN is the same, we can safely ignore this fragment. Though the loop
			// above checks the exact same condition, so this is redundant, and here for
			// clarity.
			return nil
		}
		// If this is indeed the first fragment, we set the flag and the TSN value.
		l.BeginFragment = true
		l.BeginTSN = f.TSN
	}

	// The last fragment of a message is special because it indicates that the
	// message is complete and that no more fragments with TSNs greater than this one
	// will be received.
	if f.EndFragment {
		// If we've already seen the last fragment, we cannot insert another one unless
		// it is the same TSN (due to retransmissions).
		if l.EndFragment {
			if f.TSN != l.EndTSN {
				return fmt.Errorf("message already ended with TSN %v", l.EndTSN)
			}
			// If the TSN is the same, we can safely ignore this fragment. Though the loop
			// above checks the exact same condition, so this is redundant, and here for
			// clarity.
			return nil
		}
		// If this is indeed the last fragment, we set the flag and the TSN value.
		l.EndFragment = true
		l.EndTSN = f.TSN
	}

	// If we get here, we have a new fragment to insert.
	l.List = append(l.List, f)
	return nil
}

var (
	errMissingFragments     = errors.New("fragments are not strictly sequential")
	errMissingBeginFragment = errors.New("missing first fragment")
	errMissingEndFragment   = errors.New("missing last fragment")
)

// Defragment reassembles the fragments into a continuous byte slice that can be
// used as the UserData field of a DATA chunk.
//
// This function assumes that all message fragments have been collected (that is,
// no chunk is missing from the sequence). It doesn't check for missing
// fragments; callers must ensure that all fragments are present before calling
// this function.
//
// It returns the total length of the reassembled message and a boolean indicating
// whether the defragmentation was successful.
func (l *fragmentList) Defragment(userData []byte) (n int, err error) {
	// First, we check if the output buffer is large enough to hold the entire
	// defragmented message.
	if size := l.TotalBytes(); len(userData) < size {
		return size, fmt.Errorf("not enough space to defragment message: %v < %v", len(userData), size)
	}

	// We may have observed fragments out-of-order, so we must sort them by TSN
	// before reassembling them, accounting for TSN wraparound.
	sort.Slice(l.List, func(i, j int) bool {
		return l.deltaTSN(l.List[i].TSN, l.List[j].TSN) < 0
	})

	// We also want to ensure that the fragments are indeed strictly sequential, as
	// the RFC mandates. Though ordered, the TSN values are not necessarily
	// consecutive. For example, we may have missed a fragment but still called this
	// function.
	for i := 1; i < len(l.List); i++ {
		prev, curr := l.List[i-1].TSN, l.List[i].TSN
		if l.deltaTSN(prev, curr) != -1 {
			return 0, errMissingFragments
		}
	}

	// We also want to ensure that the first fragment is indeed the first fragment,
	// and that the last fragment is indeed the last fragment.
	//
	// We don't need to check their TSNs because the BeginFragment and EndFragment
	// flags are set only once during Insert.
	if !l.List[0].BeginFragment {
		return 0, errMissingBeginFragment
	}
	if !l.List[len(l.List)-1].EndFragment {
		return 0, errMissingEndFragment
	}

	// All that's left now is to COPY all fragments into the chunk's content buffer.
	// Any padding bytes are already allocated and zeroed.
	var offset int
	for _, frag := range l.List {
		offset += copy(userData[offset:], frag.UserData)
	}
	return offset, nil
}

// TotalBytes trivially sums all fragments, as we don't have any padding in the
// fragments.
//
// The list of fragments is expected to be small, so we can afford to iterate
// over it without optimisations (e.g. summarising as fragments are inserted).
func (l *fragmentList) TotalBytes() (sum int) {
	for _, frag := range l.List {
		sum += len(frag.UserData)
	}
	return sum
}

// DeltaTSN calculates the difference between two TSNs, taking into account
// wraparound. It returns the difference as an int64, which can be negative if
// the first (left) TSN is greater than the second (right).
//
// The difference between two uint32 values can be at most (2^32 - 1), which is
// the maximum value of uint32, so we can safely use int64 (though not int) to
// represent that difference.
//
// Wraparound occurs when a TSN is less than the list's beginning TSN, which is
// the TSN of the first fragment in the list. The SCTP specification caps message
// size below 2^32.
func (l *fragmentList) deltaTSN(left, right uint32) int64 {
	// TODO: test this function once.
	if left == right {
		return 0
	}
	// To compare TSNs correctly accounting for wraparound, we expand them from
	// unsigned 32-bits to signed 64-bits.
	first, second := int64(left), int64(right)
	if left < l.BeginTSN {
		// We add 1 to the BeginTSN to account for the fact that 0 is a valid TSN, so we
		// need to shift the range of TSNs to start from 1.
		first += int64(l.BeginTSN) + 1
	}
	if right < l.BeginTSN {
		// We add 1 to the BeginTSN to account for the fact that 0 is a valid TSN, so we
		// need to shift the range of TSNs to start from 1.
		second += int64(l.BeginTSN) + 1
	}
	return first - second
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

// Call copyFragment to copy the payload from the given DATA chunk because
// gopacket doesn't guarantee that underlying buffers aren’t reused over time.
func copyFragment(data *layers.SCTPData) fragment {
	// We must copy the user data from the layer to ensure that it remains valid
	// until we reassemble the message.
	userData := make([]byte, len(data.UserData))
	copy(userData, data.UserData) // Copies without the padding.
	return fragment{
		TSN:           data.TSN,
		UserData:      userData,
		BeginFragment: data.BeginFragment,
		EndFragment:   data.EndFragment,
	}
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
