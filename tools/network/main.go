package network

import "net"

// retrieves information for the specified network device.
//
// Parameters:
//
//	device (string): The name of the network device for which to fetch addresses.
//
// Returns:
//
//	net.HardwareAddr: MAC address of the network device.
//	net.IP: IPv4 address of the network device.
//	net.IP: Broadcast address of the network device.
//	error: Any error encountered during the address retrieval process.
func AskNetworkInfo(interfaceName string) (net.HardwareAddr, net.IP, net.IP, error) {
	networkInfo, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return net.HardwareAddr{}, net.IP{}, net.IP{}, err
	}

	addrs, err := networkInfo.Addrs()
	if err != nil {
		return net.HardwareAddr{}, net.IP{}, net.IP{}, err
	}

	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}

		if ipNet.IP.IsLoopback() {
			continue
		}

		isIPv6 := ipNet.IP.To4() == nil
		if isIPv6 {
			continue
		}

		network := ipNet.IP.Mask(ipNet.Mask)
		broadcast := net.IP(make([]byte, 4))
		for i := 0; i < 4; i++ {
			broadcast[i] = network[i] | ^ipNet.Mask[i]
		}

		return networkInfo.HardwareAddr, ipNet.IP, broadcast, err
	}

	return net.HardwareAddr{}, net.IP{}, net.IP{}, err
}
