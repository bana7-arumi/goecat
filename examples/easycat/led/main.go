package main

import (
	"fmt"
	"log"
	"time"

	"github.com/Aruminium/goecat/pkg/ethercat/command"
	"github.com/Aruminium/goecat/pkg/ethercat/datagram"
	"github.com/Aruminium/goecat/pkg/ethercat/payload"
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

	index       uint8   = 0 // ECAT Index
	led         uint8   = 0 // EasyCAT LED
	intervalSec float64 = 0.003
	intervalSum float64 = 0.00
)

const (
	LED_MAX uint8 = 0x0f
)

func main() {
	handle, err := pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	pac, err := packet.NewEtherCATPacket(device)
	if err != nil {
		log.Fatal(err)
	}

	// LEDの値を規定時間経過で+1する
	// LEDの値が0x00 ~ 0x0fになるまで処理を行う
	for {
		ecatDatagram1 := datagram.Datagram{
			Command: command.LWR,
			Index:   uint8(index),
			Address: uint32(0x00000000),
			LRCM:    datagram.NewLrcm(true, false, 64),
			IRQ:     uint16(0x0000),
			Data: payload.BasicPayload{Data: []byte{
				led, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				led, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0}},
			WKC: uint16(0x0000),
		}

		index++
		ecatDatagram2 := datagram.Datagram{
			Command: command.LRD,
			Index:   uint8(index),
			Address: uint32(0x00000000),
			LRCM:    datagram.NewLrcm(true, false, 64),
			IRQ:     uint16(0x0000),
			Data: payload.BasicPayload{Data: []byte{
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0}},
			WKC: uint16(0),
		}

		index++
		ecatDatagram3 := datagram.Datagram{
			Command: command.BRD,
			Index:   uint8(index),
			Address: uint32(0x00000000),
			LRCM:    datagram.NewLrcm(false, false, 1),
			IRQ:     uint16(0x0000),
			Data:    payload.BasicPayload{Data: []byte{0}},
			WKC:     uint16(0),
		}

		pac.Ecat.AppendDatagram(ecatDatagram1)
		pac.Ecat.AppendDatagram(ecatDatagram2)
		pac.Ecat.AppendDatagram(ecatDatagram3)

		_, err = pac.Send(handle, options)
		if err != nil {
			fmt.Printf("[-] Error while sending: %s\n", err.Error())
			return
		}

		time.Sleep(time.Duration(intervalSec * float64(time.Second)))
		// 次のloopに向けたセットアップ処理
		intervalSum += intervalSec
		index++
		if intervalSum >= 1.0 {
			intervalSum = 0.0
			led = (led + 1) % 0x10
			fmt.Printf("1秒経過 => Next LED Value: %d\n", led)
		}
	}
}
