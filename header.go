package utp

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	extensionTypeSelectiveAck = 1
)

type extensionField struct {
	Type  byte
	Bytes []byte
}

type header struct {
	Type          st
	Version       int
	ConnID        uint16
	Timestamp     uint32
	TimestampDiff uint32
	WndSize       uint32
	SeqNr         uint16
	AckNr         uint16
	Extensions    []extensionField
}

func unmarshalExtensions(_type byte, b []byte) (n int, ef []extensionField, err error) {
	for _type != 0 {
		if _type != extensionTypeSelectiveAck {
			// An extension type that is not known to us. Generally we're
			// unmarshalling an packet that isn't actually uTP but we don't
			// yet know for sure until we try to deliver it.

			// logonce.Stderr.Printf("utp extension %d", _type)
		}
		if len(b) < 2 || len(b) < int(b[1])+2 {
			err = fmt.Errorf("buffer ends prematurely: %x", b)
			return
		}
		ef = append(ef, extensionField{
			Type:  _type,
			Bytes: append([]byte(nil), b[2:int(b[1])+2]...),
		})
		_type = b[0]
		n += 2 + int(b[1])
		b = b[2+int(b[1]):]
	}
	return
}

var errInvalidHeader = errors.New("invalid header")

func (h *header) Unmarshal(b []byte) (n int, err error) {
	h.Type = st(b[0] >> 4)
	h.Version = int(b[0] & 0xf)
	if h.Type > stMax || h.Version != 1 {
		err = errInvalidHeader
		return
	}
	n, h.Extensions, err = unmarshalExtensions(b[1], b[20:])
	if err != nil {
		return
	}
	h.ConnID = binary.BigEndian.Uint16(b[2:4])
	h.Timestamp = binary.BigEndian.Uint32(b[4:8])
	h.TimestampDiff = binary.BigEndian.Uint32(b[8:12])
	h.WndSize = binary.BigEndian.Uint32(b[12:16])
	h.SeqNr = binary.BigEndian.Uint16(b[16:18])
	h.AckNr = binary.BigEndian.Uint16(b[18:20])
	n += 20
	return
}

func (h *header) Marshal(p []byte) (n int) {
	n = 20 + func() (ret int) {
		for _, ext := range h.Extensions {
			ret += 2 + len(ext.Bytes)
		}
		return
	}()
	p = p[:n]
	p[0] = byte(h.Type<<4 | 1)
	binary.BigEndian.PutUint16(p[2:4], h.ConnID)
	binary.BigEndian.PutUint32(p[4:8], h.Timestamp)
	binary.BigEndian.PutUint32(p[8:12], h.TimestampDiff)
	binary.BigEndian.PutUint32(p[12:16], h.WndSize)
	binary.BigEndian.PutUint16(p[16:18], h.SeqNr)
	binary.BigEndian.PutUint16(p[18:20], h.AckNr)
	// Pointer to the last type field so the next extension can set it.
	_type := &p[1]
	// We're done with the basic header.
	p = p[20:]
	for _, ext := range h.Extensions {
		*_type = ext.Type
		// The next extension's type will go here.
		_type = &p[0]
		p[1] = uint8(len(ext.Bytes))
		if int(p[1]) != copy(p[2:], ext.Bytes) {
			panic("unexpected extension length")
		}
		p = p[2+len(ext.Bytes):]
	}
	*_type = 0
	if len(p) != 0 {
		panic("header length changed")
	}
	return
}

type selectiveAckBitmask struct {
	Bytes []byte
}

func (me *selectiveAckBitmask) expandBytesForBit(index int) {
	minLen := (3 + (index / 8) + 1) / 4 * 4
	for len(me.Bytes) < minLen {
		me.Bytes = append(me.Bytes, 0)
	}
}

func (me *selectiveAckBitmask) NumBits() int {
	return len(me.Bytes) * 8
}

func (me *selectiveAckBitmask) SetBit(index int) {
	me.expandBytesForBit(index)
	me.Bytes[index/8] |= 1 << uint(index%8)
}

func (me *selectiveAckBitmask) BitIsSet(index int) bool {
	return me.Bytes[index/8]>>uint(index%8)&1 == 1
}

// selectiveAckRanges implements QUIC-style range-based selective ACK.
// Format: [N (1 byte)][offset, length (2+2 bytes) x N]
// Total max: 32 bytes (1 + 7 * 4)
type selectiveAckRanges struct {
	ranges [][2]uint16 // [offset, length] pairs relative to AckNr
}

const maxSackRanges = 7

// buildFromBitmask creates ranges from a bitmask (for compatibility/transition)
func (me *selectiveAckRanges) buildFromBitmask(bitmask selectiveAckBitmask) {
	me.ranges = nil
	var currentOffset uint16
	var currentLength uint16

	for i := 0; i < bitmask.NumBits(); i++ {
		if bitmask.BitIsSet(i) {
			if currentLength == 0 {
				currentOffset = uint16(i)
				currentLength = 1
			} else {
				currentLength++
			}
		} else if currentLength > 0 {
			me.ranges = append(me.ranges, [2]uint16{currentOffset, currentLength})
			currentLength = 0
		}
	}

	if currentLength > 0 {
		me.ranges = append(me.ranges, [2]uint16{currentOffset, currentLength})
	}
}

// Marshal encodes ranges into bytes (always 32 bytes = 256 bits)
// This maintains protocol compatibility with standard BitTorrent uTP
// Format: [N (1 byte)][offset, length (2+2 bytes) x N][padding to 32]
func (me *selectiveAckRanges) Marshal() []byte {
	numRanges := len(me.ranges)
	if numRanges > maxSackRanges {
		numRanges = maxSackRanges
	}
	result := make([]byte, 32) // Always 32 bytes
	result[0] = byte(numRanges)
	for i := 0; i < numRanges; i++ {
		binary.BigEndian.PutUint16(result[1+i*4:], me.ranges[i][0])
		binary.BigEndian.PutUint16(result[3+i*4:], me.ranges[i][1])
	}
	return result
}

// NumPackets returns total number of packets covered by all ranges
func (me *selectiveAckRanges) NumPackets() int {
	total := 0
	for _, r := range me.ranges {
		total += int(r[1])
	}
	return total
}

// Range returns offset and length for range i
func (me *selectiveAckRanges) Range(i int) (offset, length uint16) {
	if i >= 0 && i < len(me.ranges) {
		return me.ranges[i][0], me.ranges[i][1]
	}
	return 0, 0
}

// NumRanges returns the number of ranges
func (me *selectiveAckRanges) NumRanges() int {
	return len(me.ranges)
}
