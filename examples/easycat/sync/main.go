package main

import (
	"fmt"
	"log"
	"time"

	"github.com/Aruminium/goecat/pkg/ethercat/command"
	"github.com/Aruminium/goecat/pkg/ethercat/datagram"
	"github.com/Aruminium/goecat/pkg/ethercat/payload"
	"github.com/Aruminium/goecat/pkg/ethercat/payload/fmmu"
	"github.com/Aruminium/goecat/pkg/ethercat/payload/syncmanager"
	"github.com/Aruminium/goecat/tools/packet"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var (
	device       string                    = "en7"
	snapshot_len int32                     = 1024
	promiscuous  bool                      = false
	timeout      time.Duration             = 30 * time.Second
	options      gopacket.SerializeOptions = gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	handle *pcap.Handle
	err    error

	d        *datagram.Datagram
	pac      packet.EtherCATPacket
	sm       *syncmanager.SyncManager
	fm       *fmmu.FMMU
	index    uint8   = 0
	duration float64 = 0.003
)

func main() {
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	pac, err = packet.NewEtherCATPacket(device)
	if err != nil {
		log.Fatal(err)
	}

	clear()
	sync()
}

func clear() {
	d = &datagram.Datagram{
		Command: command.BRD,
		Index:   uint8(index),
		Address: uint32(0x00000000),
		LRCM:    datagram.NewLrcm(false, false, 1),
		IRQ:     uint16(0x0000),
		Data:    payload.BasicPayload{Data: []byte{0x00}},
		WKC:     uint16(0x0000),
	}
	handler(d)

	d = &datagram.Datagram{
		Command: command.BWR,
		Index:   uint8(index),
		Address: uint32(0x00000800),
		LRCM:    datagram.NewLrcm(false, false, 64),
		IRQ:     uint16(0x0000),
		Data: payload.BasicPayload{Data: []byte{
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		}},
		WKC: uint16(0x0000),
	}
	handler(d)
}

func sync() {
	// SM
sm = &syncmanager.SyncManager{
	Start:  0x1000,
	Length: 0x0020,
	CtrlStatus: syncmanager.CtrlStatus{
		InVisibleBufferState:     0,
		VisibleBufferBufferState: 0,
		CanReadIRQ:               false,
		CanWriteIRQ:              false,
		IsTriggerWatchdog:        true,
		IsPdiIRQ:                 true,
		IsEcatIRQ:                false,
		Access:                   0x1,
		OpMode:                   0,
	},
	Enable: syncmanager.Enable{
		IsRepeatAcknowledge: false,
		IsDeactivate:        false,
		IsLatchChangePDI:    false,
		IsLatchChangeECAT:   false,
		IsRepeatRequest:     false,
		IsEnable:            true,
	},
}
d = &datagram.Datagram{
	Command: command.APWR,
	Index:   uint8(index),
	Address: uint32(0x00000800),
	LRCM:    datagram.NewLrcm(false, false, 8),
	IRQ:     uint16(0x0000),
	Data:    sm,
	WKC:     uint16(0x0000),
}
	handler(d)

	sm = &syncmanager.SyncManager{
		Start:  0x1100,
		Length: 0x0020,
		CtrlStatus: syncmanager.CtrlStatus{
			InVisibleBufferState:     0,
			VisibleBufferBufferState: 0,
			CanReadIRQ:               false,
			CanWriteIRQ:              false,
			IsTriggerWatchdog:        true,
			IsPdiIRQ:                 true,
			IsEcatIRQ:                false,
			Access:                   0x0,
			OpMode:                   0,
		},
		Enable: syncmanager.Enable{
			IsRepeatAcknowledge: false,
			IsDeactivate:        false,
			IsLatchChangePDI:    false,
			IsLatchChangeECAT:   false,
			IsRepeatRequest:     false,
			IsEnable:            true,
		},
	}
	d = &datagram.Datagram{
		Command: command.APWR,
		Index:   uint8(index),
		Address: uint32(0x00000808),
		LRCM:    datagram.NewLrcm(false, false, 8),
		IRQ:     uint16(0x0000),
		Data:    sm,
		WKC:     uint16(0x0000),
	}
	handler(d)

	sm = &syncmanager.SyncManager{
		Start:  0x1200,
		Length: 0x0020,
		CtrlStatus: syncmanager.CtrlStatus{
			InVisibleBufferState:     0,
			VisibleBufferBufferState: 0,
			CanReadIRQ:               false,
			CanWriteIRQ:              false,
			IsTriggerWatchdog:        true,
			IsPdiIRQ:                 true,
			IsEcatIRQ:                false,
			Access:                   0x0,
			OpMode:                   0,
		},
		Enable: syncmanager.Enable{
			IsRepeatAcknowledge: false,
			IsDeactivate:        false,
			IsLatchChangePDI:    false,
			IsLatchChangeECAT:   false,
			IsRepeatRequest:     false,
			IsEnable:            true,
		},
	}
	d = &datagram.Datagram{
		Command: command.APWR,
		Index:   uint8(index),
		Address: uint32(0x00000810),
		LRCM:    datagram.NewLrcm(false, false, 8),
		IRQ:     uint16(0x0000),
		Data:    sm,
		WKC:     uint16(0x0000),
	}
	handler(d)

	sm = &syncmanager.SyncManager{
		Start:  0x1300,
		Length: 0x0020,
		CtrlStatus: syncmanager.CtrlStatus{
			InVisibleBufferState:     0,
			VisibleBufferBufferState: 0,
			CanReadIRQ:               false,
			CanWriteIRQ:              false,
			IsTriggerWatchdog:        true,
			IsPdiIRQ:                 true,
			IsEcatIRQ:                false,
			Access:                   0x0,
			OpMode:                   0,
		},
		Enable: syncmanager.Enable{
			IsRepeatAcknowledge: false,
			IsDeactivate:        false,
			IsLatchChangePDI:    false,
			IsLatchChangeECAT:   false,
			IsRepeatRequest:     false,
			IsEnable:            true,
		},
	}
	d = &datagram.Datagram{
		Command: command.APWR,
		Index:   uint8(index),
		Address: uint32(0x00000818),
		LRCM:    datagram.NewLrcm(false, false, 8),
		IRQ:     uint16(0x0000),
		Data:    sm,
		WKC:     uint16(0x0000),
	}
	handler(d)

	fm = &fmmu.FMMU{
		LogStart:     0,
		LogLength:    0x0020,
		LogStartBit:  0,
		LogEndBit:    0x07,
		PhysStart:    0x1300,
		PhysStartBit: 0,
		AbleUseRead:  false,
		AbleUseWrite: true,
		IsActivate:   true,
	}
	d = &datagram.Datagram{
		Command: command.APWR,
		Index:   uint8(index),
		Address: uint32(0x00000630),
		LRCM:    datagram.NewLrcm(false, false, 16),
		IRQ:     uint16(0x0000),
		Data:    fm,
		WKC:     uint16(0x0000),
	}
	handler(d)

	fm = &fmmu.FMMU{
		LogStart:     0,
		LogLength:    0x0020,
		LogStartBit:  0,
		LogEndBit:    0x07,
		PhysStart:    0x1200,
		PhysStartBit: 0,
		AbleUseRead:  true,
		AbleUseWrite: true,
		IsActivate:   true,
	}
	d = &datagram.Datagram{
		Command: command.APWR,
		Index:   uint8(index),
		Address: uint32(0x00000620),
		LRCM:    datagram.NewLrcm(false, false, 16),
		IRQ:     uint16(0x0000),
		Data:    fm,
		WKC:     uint16(0x0000),
	}
	handler(d)

	fm = &fmmu.FMMU{
		LogStart:     0,
		LogLength:    0x0020,
		LogStartBit:  0,
		LogEndBit:    0x07,
		PhysStart:    0x1100,
		PhysStartBit: 0,
		AbleUseRead:  false,
		AbleUseWrite: true,
		IsActivate:   true,
	}
	d = &datagram.Datagram{
		Command: command.APWR,
		Index:   uint8(index),
		Address: uint32(0x00000610),
		LRCM:    datagram.NewLrcm(false, false, 16),
		IRQ:     uint16(0x0000),
		Data:    fm,
		WKC:     uint16(0x0000),
	}
	handler(d)

	fm = &fmmu.FMMU{
		LogStart:     0,
		LogLength:    0x0020,
		LogStartBit:  0,
		LogEndBit:    0x07,
		PhysStart:    0x1000,
		PhysStartBit: 0,
		AbleUseRead:  true,
		AbleUseWrite: true,
		IsActivate:   true,
	}
	d = &datagram.Datagram{
		Command: command.APWR,
		Index:   uint8(index),
		Address: uint32(0x00000600),
		LRCM:    datagram.NewLrcm(false, false, 16),
		IRQ:     uint16(0x0000),
		Data:    fm,
		WKC:     uint16(0x0000),
	}
	handler(d)

	d = &datagram.Datagram{
		Command: command.BWR,
		Index:   uint8(index),
		Address: uint32(0x00000120),
		LRCM:    datagram.NewLrcm(false, false, 1),
		IRQ:     uint16(0x0000),
		Data:    payload.BasicPayload{Data: []byte{0x08}},
		WKC:     uint16(0x0000),
	}
	handler(d)
}

func handler(d *datagram.Datagram) {
	pac.Ecat.AppendDatagram(*d)
	_, err = pac.Send(handle, options)
	if err != nil {
		fmt.Printf("[-] Error while sending: %s\n", err.Error())
	}
	time.Sleep(time.Duration(duration * float64(time.Second)))
	index++
}
