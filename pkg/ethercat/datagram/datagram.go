package datagram

import (
	"encoding/binary"

	"github.com/Aruminium/goecat/pkg/ethercat/command"
)

// EcatDatagram represents an EtherCAT datagram.
//
// It contains various fields including the EtherCAT command type, index,
// address, LRCM (Length, Reserved, Circulating Frame, More EtherCAT Data),
// IRQ (EtherCAT Event Request registers of all slaves combined with a logical OR),
// data for read/write operations, and the working counter.
type Datagram struct {
	Command command.Type // EtherCAT Command Type
	Index   uint8        // The index is a numeric identifier used by the master for identification of duplicates/lost datagrams. It shall not be changed by EtherCAT slaves
	Address uint32       // Address (Auto Increment, Configured Station Address, or Logical Address)
	LRCM    Lrcm         // LRCM represents the Len, R, C, M fields in the EtherCAT Datagram header.
	IRQ     uint16       // EtherCAT Event Request registers of all slaves combined with a logical OR
	Data    []byte       // Read/Write Data
	WKC     uint16       // Working Counter
}

// Bytes returns the byte representation of the EtherCAT datagram.
//
// Returns:
//   - []byte: The byte representation of the EtherCAT datagram.
func (e Datagram) Bytes() []byte {
	result := make([]byte, 0)

	result = append(result, uint8(e.Command))

	result = append(result, e.Index)

	addressBytes := make([]byte, 4)
	// Upper 16 bits is LittleEndian
	binary.LittleEndian.PutUint16(addressBytes, uint16(e.Address>>16))
	// Lower 16bit is LittleEndian
	binary.LittleEndian.PutUint16(addressBytes[2:], uint16(e.Address))
	result = append(result, addressBytes...)

	lrcmBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(lrcmBytes, e.LRCM.Uint16())
	result = append(result, lrcmBytes...)

	irqBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(irqBytes, e.IRQ)
	result = append(result, irqBytes...)

	result = append(result, e.Data...)

	wkcBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(wkcBytes, e.WKC)
	result = append(result, wkcBytes...)

	return result
}
