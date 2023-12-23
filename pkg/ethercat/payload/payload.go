// Package payload provides interfaces and types for working with data payloads.
package payload

// MarshalerByte is an interface for types that can marshal themselves into a byte slice.
type MarshalerByte interface {
	// Bytes returns the byte representation of the implementing type.
	Bytes() []byte
}

// BasicPayload is a simple implementation of the MarshalerByte interface.
type BasicPayload struct {
	// Data holds the byte data of the payload.
	Data []byte
}

// Bytes returns the byte representation of the BasicPayload.
// It implements the Bytes method of the MarshalerByte interface.
func (p BasicPayload) Bytes() []byte {
	return p.Data
}
