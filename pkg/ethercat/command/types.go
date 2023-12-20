package command

// EcatCommand represents EtherCAT command types for Read/Write operations.
//
// For ReadWrite operations, the Read operation is performed before the Write operation.
type Type uint8

const (
	NOP  Type = 0  // No Operation
	APRD Type = 1  // Auto Increment Read
	APWR Type = 2  // Auto Increment Write
	APRW Type = 3  // Auto Increment Read Write
	FPRD Type = 4  // Configured Address Read
	FPWR Type = 5  // Configured Address Write
	FPRW Type = 6  // Configured Address Read Write
	BRD  Type = 7  // Broadcast Read
	BWR  Type = 8  // Broadcast Write
	BRW  Type = 9  // Broadcast Read Write
	LRD  Type = 10 // Logical Memory Read
	LWR  Type = 11 // Logical Memory Write
	LRW  Type = 12 // Logical Memory Read Write
	ARMW Type = 13 // Auto Increment Read Multiple Write
	FRMW Type = 14 // Configured Read Multiple Write
)
