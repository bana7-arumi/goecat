package packet

import (
	"net"

	"github.com/Aruminium/goecat/pkg/ethercat"
	"github.com/Aruminium/goecat/tools/network"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type EtherCATPacket struct {
	Ethernet *layers.Ethernet
	IPv4     *layers.IPv4
	UDP      *layers.UDP
	Ecat     *ethercat.EtherCAT
}

func NewEtherCATPacket(device string) (EtherCATPacket, error) {
	srcMAC, yourIP, broIP, err := network.AskNetworkInfo(device)
	if err != nil {
		return EtherCATPacket{}, err
	}

	dstMAC, _ := net.ParseMAC("ff:ff:ff:ff:ff:ff")
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    yourIP,
		DstIP:    broIP,
		Protocol: layers.IPProtocolUDP,
	}

	udp := &layers.UDP{
		SrcPort: layers.UDPPort(34980),
		DstPort: layers.UDPPort(34980),
	}
	udp.SetNetworkLayerForChecksum(ip)

	ecat := ethercat.NewEtherCAT()

	return EtherCATPacket{Ethernet: eth, IPv4: ip, UDP: udp, Ecat: ecat}, nil
}

func (p *EtherCATPacket) Send(handle *pcap.Handle, options gopacket.SerializeOptions) ([]byte, error) {
	buffer := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, options,
		p.Ethernet,
		p.IPv4,
		p.UDP,
		gopacket.Payload(p.Ecat.Bytes()),
	)

	data := buffer.Bytes()
	buffer.Clear()

	if err := handle.WritePacketData(data); err != nil {
		return []byte{}, err
	}

	return data, nil
}
