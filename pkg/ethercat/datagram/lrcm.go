package datagram

// Lrcm represents the Len, R, C, M fields in the EtherCAT Datagram header.
//
// ----------------- LRCM ---------------------
//
// | M: 1bit | C: 1bit | R: 3bit | Len: 11bit |
//
// --------------------------------------------
type Lrcm struct {
	M   bool   // M: 1 bit (More EtherCAT Data)
	C   bool   // C: 1 bit (Circulating Frame)
	R   uint16 // R: 3 bit (Reserved)
	Len uint16 // Len: 11 bits (Paylod Length)
}

// NewLrcm creates a new Lrcm instance with the specified values for M, C, and Len.
//
// Parameters:
//   - m: More EtherCAT Data field (1 bit, {0: last, 1: more})
//   - c: Circulating Frame field (1 bit, {0: not, 1: circulating})
//   - len: Payload Length field (11 bits, valid values: 0 to 2047)
//
// Returns:
//   - Lrcm: New Lrcm instance
//   - error: An error is returned if the provided values are out of valid range.
func NewLrcm(isMore bool, isCirculating bool, len uint16) Lrcm {
	return Lrcm{Len: len, R: 0, C: isCirculating, M: isMore}
}

// NEWLrcmFromUint16 creates an Lrcm instance from a uint16 value.
//
// Parameters:
//   - l: The uint16 value representing Lrcm fields.
//
// Returns:
//   - Lrcm: New Lrcm instance
func NEWLrcmFromUint16(l uint16) Lrcm {
	m := 1 == (l&0b1000000000000000)>>15
	c := 1 == (l&0b0100000000000000)>>14
	r := (l & 0b0011100000000000) >> 11
	len := (l & 0b0000011111111111)

	return Lrcm{M: m, C: c, R: r, Len: len}
}

// Uint16 returns the uint16 representation of the Lrcm instance.
//
// Returns:
//   - uint16: The uint16 value representing Lrcm fields.
func (Lrcm Lrcm) Uint16() uint16 {
	mBits := uint16(0)
	if Lrcm.M {
		mBits = 0b1000000000000000
	}

	cBits := uint16(0)
	if Lrcm.C {
		mBits = 0b0100000000000000
	}

	rBits := Lrcm.R << 11

	return mBits | cBits | rBits | Lrcm.Len
}
