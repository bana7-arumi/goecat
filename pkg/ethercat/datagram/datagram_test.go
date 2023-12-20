package datagram_test

import (
	"reflect"
	"testing"

	"github.com/Aruminium/goecat/pkg/ethercat/command"
	"github.com/Aruminium/goecat/pkg/ethercat/datagram"
)

func Test1EcatDatagramBytes(t *testing.T) {
	// test1
	lrcm := datagram.NEWLrcmFromUint16(170)

	datagram := datagram.Datagram{
		Command: command.NOP,
		Index:   5,
		Address: 0x00ff00ff, // 0, 255, 0, 255
		LRCM:    lrcm,       // 0, 170
		IRQ:     0x0000,
		Data:    []byte{0x01, 0x02, 0x03},
		WKC:     0x0001,
	}

	expectedBytes := []byte{0, 5, 255, 0, 255, 0, 170, 0, 0, 0, 1, 2, 3, 1, 0}

	resultBytes := datagram.Bytes()

	if !reflect.DeepEqual(resultBytes, expectedBytes) {
		t.Errorf("Expected Bytes: %v, Got: %v", expectedBytes, resultBytes)
	}
}

func Test2EcatDatagramBytes(t *testing.T) {
	lrcm := datagram.NewLrcm(0, 0, 8)
	datagram := datagram.Datagram{
		Command: command.APWR,
		Index:   uint8(0x5f),
		Address: uint32(0xffff0800),
		LRCM:    lrcm,
		IRQ:     uint16(0x0000),
		Data:    []byte{0x00, 0x18, 0x30, 0x00, 0x26, 0x00, 0x01, 0x00},
		WKC:     uint16(0x0000),
	}

	expectedBytes := []byte{0x02, 0x5f, 0xff, 0xff, 0x00, 0x08, 0x08, 0x00, 0x00, 0x00, 0x00, 0x18, 0x30, 0x00, 0x26, 0x00,
		0x01, 0x00, 0x00, 0x00}

	resultBytes := datagram.Bytes()

	if !reflect.DeepEqual(resultBytes, expectedBytes) {
		t.Errorf("Expected Bytes: %v, Got: %v", expectedBytes, resultBytes)
	}
}
