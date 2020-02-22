package main

import (
	"flag"
	"fmt"
	arp "github.com/pefish/go-arping"
	"github.com/pefish/go-net-arp"
	"log"
	"net"
	"time"
)

var (
	ifaceFlag = flag.String("i", "eth0", "network interface to use for ARP request")

	ipFlag = flag.String("ip", "", "IPv4 address destination for ARP request")
)


func main() {
	flag.Parse()

	ifi, err := net.InterfaceByName(*ifaceFlag)
	if err != nil {
		log.Fatal(err)
	}

	c, err := arp.Dial(ifi)
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()


	if err := c.SetDeadline(time.Now().Add(time.Second)); err != nil {
		log.Fatal(err)
	}

	ip := net.ParseIP(*ipFlag).To4()

	err = c.Request(ip) // 发出arp请求
	if err != nil {
		log.Fatal(err)
	}

	var mac net.HardwareAddr
	// 循环等待回复
	for {
		arp_, _, err := c.Read()
		if err != nil {
			log.Fatal(err)
		}

		if arp_.Operation != net_arp.OperationReply || !arp_.SenderIP.Equal(ip) {
			continue
		}
		mac = arp_.SenderHardwareAddr
		break
	}

	fmt.Printf("ip: %s -> mac地址: %s\n", ip, mac)
}
