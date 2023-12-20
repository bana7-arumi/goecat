package header

import "errors"

// Header represents an EtherCAT frame header.
//
// The header consists of 11 bits for length, 1 bit reserved,
// and 4 bits for the type.
//
// ----------------- EtherCat Header -----------------
//
// | EcatType: 4bit | Reserved: 1bit | Length: 11bit |
//
// ---------------------------------------------------
type Header struct {
	ecatType uint16 // Type: Protocol type. Only EtherCAT commands (Type = 0x1) are supported by ESCs.
	res      uint16 // Reserved: Reserved, 0
	length   uint16 // Length: Length of the EtherCAT datagrams
}

// DefaultEcatHeader creates and returns a default EtherCAT header with EcatType=1, Reserved=0, and Length=0.
//
// Returns:
//   - EcatHeader: Default EtherCAT header
func DefaultEcatHeader() Header {
	return Header{1, 0, 0}
}

// NewEcatHeader creates a new EtherCAT header with the specified length.
// It returns an error if the provided length is outside the valid range [0, 2047].
//
// Parameters:
//   - length (uint16): Length value for the EtherCAT header
//
// Returns:
//   - EcatHeader: New EtherCAT header
//   - error: Error if length is outside the valid range
func NewEcatHeader(length uint16) (Header, error) {
	if length >= 2048 {
		return Header{}, errors.New("invalid value for Ecat Header Length: Length must be in the range [0, 2047]")
	}

	return Header{1, 0, length}, nil
}

// ExtractLength returns the length value from the EtherCAT header.
//
// Returns:
//   - uint16: Length value from the EtherCAT header
func (e Header) ExtractLength() uint16 {
	return e.length
}

// Uint16 returns the uint16 representation of the EtherCAT header.
//
// Returns:
//   - uint16: Uint16 representation of the EtherCAT header
func (e Header) Uint16() uint16 {
	ecatTypeBits := e.ecatType << 12
	resBits := e.res << 11
	lengthBits := e.length & 0b0000011111111111

	return uint16(ecatTypeBits) | uint16(resBits) | lengthBits
}
