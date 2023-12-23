package fmmu

import "encoding/binary"

type FMMU struct {
	LogStart     uint32
	LogLength    uint16
	LogStartBit  uint8
	LogEndBit    uint8
	PhysStart    uint16
	PhysStartBit uint8
	AbleUseRead  bool
	AbleUseWrite bool
	IsActivate   bool
}

func (f FMMU) Bytes() []byte {
	result := make([]byte, 0)

	logStartBits := make([]byte, 4)
	binary.LittleEndian.PutUint32(logStartBits, f.LogStart)
	result = append(result, logStartBits...)

	logLengthBits := make([]byte, 2)
	binary.LittleEndian.PutUint16(logLengthBits, f.LogLength)
	result = append(result, logLengthBits...)

	result = append(result, f.LogStartBit)

	result = append(result, f.LogEndBit)

	physStartBits := make([]byte, 2)
	binary.LittleEndian.PutUint16(physStartBits, f.PhysStart)
	result = append(result, physStartBits...)

	result = append(result, f.PhysStartBit)

	typeBits := uint8(0)
	if f.AbleUseRead {
		typeBits |= 0b1
	}
	if f.AbleUseWrite {
		typeBits |= 0b10
	}
	result = append(result, typeBits)

	activateBits := uint8(0)
	if f.IsActivate {
		activateBits |= 0b1
	}
	result = append(result, activateBits)

	return result
}
