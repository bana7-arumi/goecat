package payload

type MarshalerByte interface {
	Bytes() []byte
}

type BasicPayload struct {
	Data []byte
}

func (p BasicPayload) Bytes() []byte {
	return p.Data
}
