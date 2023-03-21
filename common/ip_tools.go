package common

import (
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"sort"
	"strconv"
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
	ones, bits := ipNet.Mask.Size()
	n := bits - ones
	ip := IPv42Unit32(ipNet.IP)
	start, end = ip>>n<<n, ip|((uint32(1)<<n)-1)
	return
}

func InternalIPInit(url string) (reduceIPRange [][]uint32, err error) {
	// http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest
	resp, err := http.Get(url)
	if err != nil {
		return
	}
	reader := csv.NewReader(resp.Body)
	reader.Comma = '|'
	reader.Comment = '#'
	reader.FieldsPerRecord = -1
	ipRanges := make([][]uint32, 0)

	record := []string{}
	for {
		record, err = reader.Read()
		if err == io.EOF {
			err = nil
			break
		}
		if err != nil {
			return
		}
		if len(record) >= 7 && record[1] == "CN" && record[2] == "ipv4" {
			bit, _ := strconv.ParseFloat(record[4], 64)
			ipcidr := fmt.Sprintf("%s/%d", record[3], 32-int(math.Log2(bit)))
			ip, ipNet, _ := net.ParseCIDR(ipcidr)
			ipNet.IP = ip
			start, end, _ := PrivateIPv4Range(ipNet)
			ipRanges = append(ipRanges, []uint32{start, end})
		}
	}
	sort.Slice(ipRanges, func(i, j int) bool {
		if ipRanges[i][0] == ipRanges[j][0] {
			return ipRanges[i][1] > ipRanges[j][1]
		}
		return ipRanges[i][0] < ipRanges[j][0]
	})
	pre := []uint32{0, 0}
	for _, rang := range ipRanges {
		if rang[0] == pre[0] {
			continue
		}
		if rang[0]-1 <= pre[1] {
			pre[1] = rang[1]
			reduceIPRange[len(reduceIPRange)-1][1] = rang[1]
		} else {
			pre = rang
			reduceIPRange = append(reduceIPRange, rang)
		}
	}
	return
}

func IsInternal(ipRange [][]uint32, ip string) bool {
	ipAddr := net.ParseIP(ip)
	val := IPv42Unit32(ipAddr)
	n := len(ipRange)
	index := sort.Search(n, func(i int) bool {
		return ipRange[i][0] >= val
	})
	if index > 0 {
		index -= 1
	}
	return val <= ipRange[index][1]
}

func Checksum(data []byte) uint16 {
	var sum uint32

	// Add all 16-bit words in the data
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}

	// If the data has odd length, add the last byte as a 16-bit word with zero padding
	if len(data)%2 != 0 {
		sum += uint32(data[len(data)-1]) << 8
	}

	// Fold the 32-bit sum to 16 bits
	for (sum >> 16) != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	// Take the one's complement of the sum
	checksum := uint16(^sum)

	return checksum
}