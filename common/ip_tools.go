package common

import (
	"encoding/binary"
	"errors"
	"net"
)

func IsIPv4Packet(packet []byte) bool {
	return len(packet) > 0 && packet[0]&0xf0 == 0x40
}

func IsIPv6Packet(packet []byte) bool {
	return len(packet) > 0 && packet[0]&0xf0 == 0x60
}

func IPv42Unit32(ip net.IP) uint32 {
	return binary.BigEndian.Uint32(ip[12:])
}

func Unit322IPv4(n uint32) net.IP {
	ipBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(ipBytes, n)
	return net.IPv4(ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3])
}

func PrivateIPv4Range(ipNet *net.IPNet) (start, end uint32, err error) {
	if !ipNet.IP.IsPrivate() {
		err = errors.New("非私有地址")
		return
	}
	ones, bits := ipNet.Mask.Size()
	n := bits - ones
	ip := IPv42Unit32(ipNet.IP)
	start, end = ip>>n<<n, ip|((uint32(1)<<n)-1)
	return
}
