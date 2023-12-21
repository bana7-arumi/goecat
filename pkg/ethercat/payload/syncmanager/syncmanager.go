package syncmanager

import "encoding/binary"

// SyncManager represents a synchronization manager with start, length, control status, and enable fields.
type SyncManager struct {
	Start      uint16
	Length     uint16
	CtrlStatus CtrlStatus
	Enable     Enable
}

// Bytes converts SyncManager to its byte representation.
// It returns the byte slice representing the SyncManager.
//
// Returns:
//   - []byte: The byte representation of the SyncManager.
func (s SyncManager) Bytes() []byte {
	result := make([]byte, 0)

	startBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(startBytes, s.Start)
	result = append(result, startBytes...)

	lengthBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(lengthBytes, s.Length)
	result = append(result, lengthBytes...)

	ctrlStatusBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(ctrlStatusBytes, s.CtrlStatus.ToUint16())
	result = append(result, ctrlStatusBytes...)

	enableBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(enableBytes, s.Enable.ToUint16())
	result = append(result, enableBytes...)

	return result
}

// CtrlStatus represents the control status with various bit fields.
type CtrlStatus struct {
	InVisibleBuffer         uint16 // [3:4]
	VisibleBufferBufferStat uint16 // [5]
	CanReadIRQ              bool   // [7]
	CanWriteIRQ             bool   // [8]
	IsTriggerWatchdog       bool   // [10]
	IsPdiIRQ                bool   // [11]
	IsEcatIRQ               bool   // [12]
	Access                  uint16 // [13:14]
	OpMode                  uint16 // [15:16]
}

// NewCtrlStatusFromUint16 creates a CtrlStatus from a uint16 value.
// It returns a pointer to the created CtrlStatus.
//
// Returns:
//   - *CtrlStatus: A pointer to the created CtrlStatus.
func NewCtrlStatusFromUint16(ctrlStatus uint16) *CtrlStatus {
	inVisibleBuffer := (ctrlStatus & 0b0011000000000000) >> 12
	visibleBuffer := (ctrlStatus & 0b0000100000000000) >> 11
	canReadIRQ := (ctrlStatus & 0b0000001000000000) == 0b0000001000000000
	canWriteIRQ := (ctrlStatus & 0b0000000100000000) == 0b0000000100000000
	isTriggerWatchdog := (ctrlStatus & 0b0000000001000000) == 0b0000000001000000
	isPdiIRQ := (ctrlStatus & 0b0000000000100000) == 0b0000000000100000
	isEcatIRQ := (ctrlStatus & 0b0000000000010000) == 0b0000000000010000
	access := (ctrlStatus & 0b0000000000001100) >> 2
	opMode := ctrlStatus & 0b00000000000011

	return &CtrlStatus{
		InVisibleBuffer:         inVisibleBuffer,
		VisibleBufferBufferStat: visibleBuffer,
		CanReadIRQ:              canReadIRQ,
		CanWriteIRQ:             canWriteIRQ,
		IsTriggerWatchdog:       isTriggerWatchdog,
		IsPdiIRQ:                isPdiIRQ,
		IsEcatIRQ:               isEcatIRQ,
		Access:                  access,
		OpMode:                  opMode,
	}
}

// ToUint16 converts CtrlStatus to its uint16 representation.
// It returns the uint16 representation of the CtrlStatus.
//
// Returns:
//   - uint16: The uint16 representation of the CtrlStatus.
func (c CtrlStatus) ToUint16() uint16 {
	inVisibleBufferBits := (c.InVisibleBuffer << 12) & 0b0011000000000000
	visibleBufferBits := (c.VisibleBufferBufferStat << 11) & 0b0000100000000000
	canReadIRQBits := uint16(0)
	if c.CanReadIRQ {
		canReadIRQBits = 0b0000001000000000
	}
	canWriteIRQBits := uint16(0)
	if c.CanWriteIRQ {
		canWriteIRQBits = 0b0000000100000000
	}
	isTriggerWatchdogBits := uint16(0)
	if c.IsTriggerWatchdog {
		isTriggerWatchdogBits = 0b0000000001000000
	}
	isPdiIRQBits := uint16(0)
	if c.IsPdiIRQ {
		isPdiIRQBits = 0b0000000000100000
	}
	isEcatIRQBits := uint16(0)
	if c.IsEcatIRQ {
		isEcatIRQBits = 0b0000000000010000
	}
	accessBits := (c.Access << 2) & 0b0000000000001100
	opModeBits := c.OpMode & 0b00000000000011

	return uint16(inVisibleBufferBits | visibleBufferBits |
		canReadIRQBits | canWriteIRQBits | isTriggerWatchdogBits | isPdiIRQBits |
		isEcatIRQBits | accessBits | opModeBits)
}

// Enable represents the enable field with various control bits.
type Enable struct {
	IsRepeatAcknowledge bool // [7]
	IsDeactivate        bool // [8]
	IsLatchChangePDI    bool // [9]
	IsLatchChangeECAT   bool // [10]
	IsRepeatRequest     bool // [15]
	IsEnable            bool // [16]
}

// NewEnableFromUint16 creates an Enable from a uint16 value.
// It returns a pointer to the created Enable.
//
// Returns:
//   - *Enable: A pointer to the created Enable.
func NewEnableFromUint16(enable uint16) *Enable {
	isRepeatAcknowledge := (enable & 0b0000001000000000) == 0b0000001000000000
	isDeactivate := (enable & 0b0000000100000000) == 0b0000000100000000
	isLatchChangePDI := (enable & 0b0000000010000000) == 0b0000000010000000
	isLatchChangeECAT := (enable & 0b0000000001000000) == 0b0000000001000000
	isRepeatRequest := (enable & 0b0000000000000010) == 0b0000000000000010
	isEnable := (enable & 1) == 1

	return &Enable{
		IsRepeatAcknowledge: isRepeatAcknowledge,
		IsDeactivate:        isDeactivate,
		IsLatchChangePDI:    isLatchChangePDI,
		IsLatchChangeECAT:   isLatchChangeECAT,
		IsRepeatRequest:     isRepeatRequest,
		IsEnable:            isEnable,
	}
}

// ToUint16 converts Enable to its uint16 representation.
// It returns the uint16 representation of the Enable.
//
// Returns:
//   - uint16: The uint16 representation of the Enable.
func (e Enable) ToUint16() uint16 {
	isRepeatAcknowledgeBits := uint16(0)
	if e.IsRepeatAcknowledge {
		isRepeatAcknowledgeBits = 0b0000001000000000
	}
	isDeactivateBits := uint16(0)
	if e.IsDeactivate {
		isDeactivateBits = 0b0000000100000000
	}
	isLatchChangePDIBits := uint16(0)
	if e.IsLatchChangePDI {
		isLatchChangePDIBits = 0b0000000010000000
	}
	isLatchChangeECATBits := uint16(0)
	if e.IsLatchChangeECAT {
		isLatchChangeECATBits = 0b0000000001000000
	}
	isRepeatRequestBits := uint16(0)
	if e.IsRepeatRequest {
		isRepeatRequestBits = 0b0000000000000010
	}
	isEnableBits := uint16(0)
	if e.IsEnable {
		isEnableBits = 1
	}

	return uint16(isRepeatAcknowledgeBits | isDeactivateBits | isLatchChangePDIBits |
		isLatchChangeECATBits | isRepeatRequestBits | isEnableBits)
}
