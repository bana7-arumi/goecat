package syncmanager_test

import (
	"reflect"
	"testing"

	"github.com/Aruminium/goecat/pkg/ethercat/payload/syncmanager"
)

func TestSyncManagerBytes(t *testing.T) {
	syncManager := syncmanager.SyncManager{
		Start:      0x1000,
		Length:     0x0020,
		CtrlStatus: *syncmanager.NewCtrlStatusFromUint16(0x0064),
		Enable:     *syncmanager.NewEnableFromUint16(0x0001),
	}

	expected := []byte{0, 16, 32, 0, 100, 0, 1, 0} // Byte representation of SyncManager
	result := syncManager.Bytes()

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v, but got %v", expected, result)
	}
}

func TestNewCtrlStatusFromUint16(t *testing.T) {
	ctrlStatusValue := uint16(0b0011101001010110) // Example CtrlStatus value
	expectedCtrlStatus := &syncmanager.CtrlStatus{
		InVisibleBufferState:     3,
		VisibleBufferBufferState: 1,
		CanReadIRQ:               true,
		CanWriteIRQ:              false,
		IsTriggerWatchdog:        true,
		IsPdiIRQ:                 false,
		IsEcatIRQ:                true,
		Access:                   1,
		OpMode:                   2,
	}

	resultCtrlStatus := syncmanager.NewCtrlStatusFromUint16(ctrlStatusValue)

	if !reflect.DeepEqual(resultCtrlStatus, expectedCtrlStatus) {
		t.Errorf("Expected %+v, but got %+v", expectedCtrlStatus, resultCtrlStatus)
	}
}

func TestCtrlStatusToUint16(t *testing.T) {
	ctrlStatus := syncmanager.CtrlStatus{
		InVisibleBufferState:     3,
		VisibleBufferBufferState: 1,
		CanReadIRQ:               true,
		CanWriteIRQ:              false,
		IsTriggerWatchdog:        true,
		IsPdiIRQ:                 false,
		IsEcatIRQ:                true,
		Access:                   1,
		OpMode:                   2,
	}

	expected := uint16(0b0011101001010110) // Expected CtrlStatus value
	result := ctrlStatus.ToUint16()

	if result != expected {
		t.Errorf("Expected %b, but got %b", expected, result)
	}
}

func TestNewEnableFromUint16(t *testing.T) {
	enableValue := uint16(0b0000001100000001) // Example Enable value
	expectedEnable := &syncmanager.Enable{
		IsRepeatAcknowledge: true,
		IsDeactivate:        true,
		IsLatchChangePDI:    false,
		IsLatchChangeECAT:   false,
		IsRepeatRequest:     false,
		IsEnable:            true,
	}

	resultEnable := syncmanager.NewEnableFromUint16(enableValue)

	if !reflect.DeepEqual(resultEnable, expectedEnable) {
		t.Errorf("Expected %+v, but got %+v", expectedEnable, resultEnable)
	}
}

func TestEnableToUint16(t *testing.T) {
	enable := syncmanager.Enable{
		IsRepeatAcknowledge: true,
		IsDeactivate:        true,
		IsLatchChangePDI:    false,
		IsLatchChangeECAT:   false,
		IsRepeatRequest:     false,
		IsEnable:            true,
	}

	expected := uint16(0b0000001100000001) // Expected Enable value
	result := enable.ToUint16()

	if result != expected {
		t.Errorf("Expected %b, but got %b", expected, result)
	}
}
