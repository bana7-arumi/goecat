package fmmu_test

import (
	"reflect"
	"testing"

	"github.com/Aruminium/goecat/pkg/ethercat/payload/fmmu"
)

func TestFMMUBytes(t *testing.T) {
	// given
	fmmu := fmmu.FMMU{
		LogStart:     0,
		LogLength:    0x0020,
		LogStartBit:  0,
		LogEndBit:    0x07,
		PhysStart:    0x1200,
		PhysStartBit: 0,
		AbleUseRead:  true,
		AbleUseWrite: false,
		IsActivate:   true,
	}

	// when
	expected := []byte{
		0x00, 0x00, 0x00, 0x00, // LogStart
		0x20, 0x00, // LogLength
		0x00,       // LogStartBit
		0x07,       // LogEndBit
		0x00, 0x12, // PhysStart
		0x00, // PhysStartBit
		0x01, // Use Type
		0x01, // Activate
	}
	result := fmmu.Bytes()

	// then
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v, but got %v", expected, result)
	}
}
