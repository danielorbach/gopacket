package defragtest

import (
	"github.com/google/gopacket"
)

// Retransmit returns a PacketDataSource that echoes the last packet read from
// the given source. All even calls (starting from 0) to ReadPacketData() will
// return fresh data from the source, while all odd calls will return the same
// data as the previous call.
//
// For example, the first call to ReadPacketData() will read from the source, and
// the next call will return the same data again.
//
// This can be used to simulate naive retransmission of a packet in tests.
func Retransmit(source gopacket.PacketDataSource) gopacket.PacketDataSource {
	return &echoPacketDataSource{base: source}
}

type echoPacketDataSource struct {
	base gopacket.PacketDataSource
	// True means that the next ReadPacketData() call will return the same data as
	// the previous one.
	pending bool
	data    []byte
	ci      gopacket.CaptureInfo
}

func (ds *echoPacketDataSource) ReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error) {
	// When pending, return the last read data and clear the pending flag.
	if ds.pending {
		ds.pending = false
		return ds.data, ds.ci, nil
	}

	data, ci, err = ds.base.ReadPacketData()
	// Errors from the base data source should not be echoed but rather returned
	// immediately, without toggling the pending state.
	if err != nil {
		return data, ci, err
	}
	ds.pending = true // Toggle.
	return ds.data, ds.ci, nil
}
