package main

import (
	"flag"
	"fmt"
	arp "github.com/pefish/go-arping"
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
	mac, err := c.Resolve(ip)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("ip: %s -> mac地址: %s", ip, mac)
}
