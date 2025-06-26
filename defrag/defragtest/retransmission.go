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
	err     error
}

func (ds *echoPacketDataSource) ReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error) {
	// If nothing is pending, read from the base data source.
	if !ds.pending {
		ds.data, ds.ci, ds.err = ds.base.ReadPacketData()
	}
	ds.pending = !ds.pending // Toggle.
	// If we just read data, return it. If we were pending, echo the last call.
	return ds.data, ds.ci, ds.err
}
