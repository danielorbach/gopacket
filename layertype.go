// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package gopacket

import (
	"fmt"
	"strconv"
)

// LayerType is a unique identifier for each type of layer.  This enumeration
// does not match with any externally available numbering scheme... it's solely
// usable/useful within this library as a means for requesting layer types
// (see Packet.Layer) and determining which types of layers have been decoded.
//
// New LayerTypes may be created by calling gopacket.RegisterLayerType.
type LayerType int64

// LayerTypeMetadata contains metadata associated with each LayerType.
type LayerTypeMetadata struct {
	// Name is the string returned by each layer type's String method.
	Name string
	// Decoder is the decoder to use when the layer type is passed in as a
	// Decoder.
	Decoder Decoder
}

type layerTypeMetadata struct {
	inUse bool
	LayerTypeMetadata
}

// DecodersByLayerName maps layer names to decoders for those layers.
// This allows users to specify decoders by name to a program and have that
// program pick the correct decoder accordingly.
var DecodersByLayerName = map[string]Decoder{}

const maxLayerType = 2000

var ltMeta [maxLayerType]layerTypeMetadata
var ltMetaMap = map[LayerType]layerTypeMetadata{}

// RegisterLayerType creates a new layer type and registers it globally.
// The number passed in must be unique, or a runtime panic will occur.  Numbers
// 0-999 are reserved for the gopacket library.  Numbers 1000-1999 should be
// used for common application-specific types, and are very fast.  Any other
// number (negative or >= 2000) may be used for uncommon application-specific
// types, and are somewhat slower (they require a map lookup over an array
// index).
func RegisterLayerType(num int, meta LayerTypeMetadata) LayerType {
	if 0 <= num && num < maxLayerType {
		if ltMeta[num].inUse {
			panic("Layer type already exists")
		}
	} else {
		if ltMetaMap[LayerType(num)].inUse {
			panic("Layer type already exists")
		}
	}
	return OverrideLayerType(num, meta)
}

// RegisterApplicationLayerType creates a new layer type and registers it globally.
// The number for the layer is set to the first available slot in the range 1111-1999,
// which is very fast (like all other layer types in the gopacket library).
// If none is available, a runtime panic will occur.
//
// This function enables other packages, in this module or external ones, to
// register application-specific type without conflicts or non-local knowledge to
// avoid them altogether.
//
// A noteworthy side effect of using this function is that the returned index may
// change depending on the context in which the calling package is used. Callers
// should take this limitation into consideration when using this function. For
// example, it may become unfeasible to rely on the layer's number when
// persisting data.
//
// To assist ever so lightly in overcoming this limitation, this function returns
// the already registered LayerType when called with an already registered layer
// name (only if it were already registered using this function).
func RegisterApplicationLayerType(meta LayerTypeMetadata) LayerType {
	for i := 1111; i < maxLayerType; i++ {
		// Reuse the number already registered for the same layer.
		if ltMeta[i].Name == meta.Name {
			return LayerType(i)
		}
		if !ltMeta[i].inUse {
			return RegisterLayerType(i, meta)
		}
	}
	panic("Could not register application layer type: the space reserved for common application-specific type is full")
}

// OverrideLayerType acts like RegisterLayerType, except that if the layer type
// has already been registered, it overrides the metadata with the passed-in
// metadata intead of panicing.
func OverrideLayerType(num int, meta LayerTypeMetadata) LayerType {
	if 0 <= num && num < maxLayerType {
		ltMeta[num] = layerTypeMetadata{
			inUse:             true,
			LayerTypeMetadata: meta,
		}
	} else {
		ltMetaMap[LayerType(num)] = layerTypeMetadata{
			inUse:             true,
			LayerTypeMetadata: meta,
		}
	}
	DecodersByLayerName[meta.Name] = meta.Decoder
	return LayerType(num)
}

// Decode decodes the given data using the decoder registered with the layer
// type.
func (t LayerType) Decode(data []byte, c PacketBuilder) error {
	var d Decoder
	if 0 <= int(t) && int(t) < maxLayerType {
		d = ltMeta[int(t)].Decoder
	} else {
		d = ltMetaMap[t].Decoder
	}
	if d != nil {
		return d.Decode(data, c)
	}
	return fmt.Errorf("Layer type %v has no associated decoder", t)
}

// String returns the string associated with this layer type.
func (t LayerType) String() (s string) {
	if 0 <= int(t) && int(t) < maxLayerType {
		s = ltMeta[int(t)].Name
	} else {
		s = ltMetaMap[t].Name
	}
	if s == "" {
		s = strconv.Itoa(int(t))
	}
	return
}
