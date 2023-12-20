package ethercat

import (
	"encoding/binary"

	"github.com/Aruminium/goecat/pkg/ethercat/datagram"
	"github.com/Aruminium/goecat/pkg/ethercat/header"
)

// ecat represents an EtherCAT packet.
type EtherCAT struct {
	header    header.Header       // EtherCAT packet header
	datagrams []datagram.Datagram // List of EtherCAT datagrams in the packet
}

// NewEcat creates and returns a new EtherCAT packet with a default header and an empty list of datagrams.
//
// Returns:
//   - ecat: New EtherCAT packet
func NewEtherCAT() *EtherCAT {
	return &EtherCAT{
		header:    header.DefaultEcatHeader(),
		datagrams: []datagram.Datagram{},
	}
}

// AppendDatagram appends a new EtherCAT datagram to the packet and updates the packet header(Length).
// It returns an error if the new header length exceeds the valid range.
//
// Parameters:
//   - data (datagram.EcatDatagram): EtherCAT datagram to append
//
// Returns:
//   - error: Error if the new header length exceeds the valid range
func (e *EtherCAT) AppendDatagram(data datagram.Datagram) error {
	newDatagramLen := len(data.Bytes()) + int(e.header.ExtractLength())

	newHeader, err := header.NewEcatHeader(uint16(newDatagramLen))
	if err != nil {
		return err
	}

	e.header = newHeader
	e.datagrams = append(e.datagrams, data)
	return nil
}

// Bytes returns the byte representation of the EtherCAT packet, including the header and datagrams.
//
// Returns:
//   - []byte: Byte representation of the EtherCAT packet
func (e EtherCAT) Bytes() []byte {
	result := make([]byte, 0)
	headerBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(headerBytes, e.header.Uint16())

	result = append(result, headerBytes...)

	for _, d := range e.datagrams {
		result = append(result, d.Bytes()...)
	}
	return result
}
