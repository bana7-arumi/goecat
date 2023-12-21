package ethercat_test

import (
	"reflect"
	"testing"

	"github.com/Aruminium/goecat/pkg/ethercat"
	"github.com/Aruminium/goecat/pkg/ethercat/command"
	"github.com/Aruminium/goecat/pkg/ethercat/datagram"
	"github.com/Aruminium/goecat/pkg/ethercat/payload"
)

func TestEcatBytes(t *testing.T) {
	// given
	ecatDatagram := datagram.Datagram{
		Command: command.APRD,
		Index:   uint8(0x29),
		Address: uint32(0xffff0008),
		LRCM:    datagram.NewLrcm(false, false, 8),
		IRQ:     uint16(0x0000),
		Data:    payload.BasicPayload{Data: []byte{0x00, 0x18, 0x30, 0x00, 0x26, 0x00, 0x01, 0x00}},
		WKC:     uint16(0x0000),
	}
	ecat := ethercat.NewEtherCAT()
	ecat.AppendDatagram(ecatDatagram)

	expectBytes := []byte{
		0x14, 0x10,
		0x01,
		0x29,
		0xff, 0xff, 0x08, 0x00,
		0x08, 0x00,
		0x00, 0x00,
		0x00, 0x18, 0x30, 0x00, 0x26, 0x00, 0x01, 0x00,
		0x00, 0x00,
	}

	// when
	ecatBytes := ecat.Bytes()

	// then
	if !reflect.DeepEqual(ecatBytes, expectBytes) {
		t.Errorf("Expected bytes to be %v, but got %v", expectBytes, ecatBytes)
	}
}
