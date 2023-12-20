package header_test

import (
	"testing"

	"github.com/Aruminium/goecat/pkg/ethercat/header"
)

func TestHeaderLength(t *testing.T) {
	// given
	header, err := header.NewEcatHeader(0x014)
	if err != nil {
		t.Failed()
	}

	expectedLength := uint16(0x014)

	// when
	result := header.ExtractLength()

	// then
	if result != expectedLength {
		t.Errorf("Expected Length: %d, Got: %d", expectedLength, result)
	}
}
