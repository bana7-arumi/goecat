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
	handle, err := pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	pac, err = packet.NewEtherCATPacket(device)
	if err != nil {
		log.Fatal(err)
	}

	d = &datagram.Datagram{
		Command: command.APRW,
		Index:   uint8(index),
		Address: uint32(0x00000500),
		LRCM:    datagram.NewLrcm(false, false, 1),
		IRQ:     uint16(0x0000),
		Data:    payload.BasicPayload{Data: []byte{0x00}},
		WKC:     uint16(0x0000),
	}
	handler(d)

	d = &datagram.Datagram{
		Command: command.APRD,
		Index:   uint8(index),
		Address: uint32(0x00000502),
		LRCM:    datagram.NewLrcm(false, false, 2),
		IRQ:     uint16(0x0000),
		Data:    payload.BasicPayload{Data: []byte{0x00, 0x00}},
		WKC:     uint16(0x0000),
	}
	handler(d)

	d = &datagram.Datagram{
		Command: command.APRD,
		Index:   uint8(index),
		Address: uint32(0x00000502),
		LRCM:    datagram.NewLrcm(false, false, 2),
		IRQ:     uint16(0x0000),
		Data:    payload.BasicPayload{Data: []byte{0x00, 0x00}},
		WKC:     uint16(0x0000),
	}
	handler(d)

	d = &datagram.Datagram{
		Command: command.APRW,
		Index:   uint8(index),
		Address: uint32(0x00000504),
		LRCM:    datagram.NewLrcm(false, false, 2),
		IRQ:     uint16(0x0000),
		Data:    payload.BasicPayload{Data: []byte{0x00, 0x00}},
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
