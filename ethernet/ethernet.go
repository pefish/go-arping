// Package ethernet implements marshaling and unmarshaling of IEEE 802.3
// Ethernet II frames and IEEE 802.1Q VLAN tags.
package ethernet

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net"
)


const (
	// 以太网帧要求的最小payload长度
	minPayload = 46
)

var (
	// 广播Mac地址
	BroadcastHardwareAddr = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
)

var (
	ErrInvalidFCS = errors.New("invalid frame check sequence")
)

type EtherType uint16

const (
	EtherTypeIPv4 EtherType = 0x0800
	EtherTypeARP  EtherType = 0x0806
	EtherTypeIPv6 EtherType = 0x86DD

	EtherTypeVLAN        EtherType = 0x8100
	EtherTypeServiceVLAN EtherType = 0x88a8
)

// 以太网帧报头数据结构
type Frame struct {
	// 网卡Mac地址。FFFFFFFFFFFF 代表所有Mac地址
	Destination net.HardwareAddr

	// 源Mac地址
	Source net.HardwareAddr

	// 用于说明VLAN成员关系和传输优先级的IEEE 802.1Q 标签 (可选)
	// 用于交换机之间传输。
	// 接入链路用于连接交换机和用户终端（如用户主机、服务器、傻瓜交换机等），只可以承载1个VLAN的数据帧
	// 干道链路用于交换机间互连或连接交换机与路由器，可以承载多个不同VLAN的数据帧
	// 在接入链路上传输的帧都是Untagged帧，在干道链路上传输的数据帧都是Tagged帧
	// 交换机内部处理的数据帧一律都是Tagged帧
	// 从用户终端接收无标记帧后，交换机会为无标记帧添加VLAN标签，重新计算帧校验序列(FCS)，然后通过干道链路发送帧
	// 向用户终端发送帧前，交换机会去除VLAN标签，并通过接入链路向终端发送无标记帧
	ServiceVLAN *VLAN

	// 与上述字段一样
	VLAN *VLAN

	// 上层协议类型。根据这个字段，操作系统会使用相应的协议解析数据帧
	// 如果这个字段的值大于等于1536，则这个帧是以太II帧，而那个字段是类型字段。
	// 否则(小于1500而大于46字节)，他是一个IEEE 802.3帧，而那个字段是长度字段
	EtherType EtherType

	// 数据
	Payload []byte
}

func (f *Frame) MarshalBinary() ([]byte, error) {
	b := make([]byte, f.length())
	_, err := f.read(b)
	return b, err
}

// 附加帧校验码。一般无需使用。操作系统会自动生成帧校验码
func (f *Frame) MarshalFCS() ([]byte, error) {
	b := make([]byte, f.length()+4)
	if _, err := f.read(b); err != nil {
		return nil, err
	}

	binary.BigEndian.PutUint32(b[len(b)-4:], crc32.ChecksumIEEE(b[0:len(b)-4]))
	return b, nil
}

func (f *Frame) read(b []byte) (int, error) {
	if f.ServiceVLAN != nil && f.VLAN == nil {
		return 0, ErrInvalidVLAN
	}

	copy(b[0:6], f.Destination)
	copy(b[6:12], f.Source)

	vlans := []struct {
		vlan *VLAN
		tpid EtherType
	}{
		{vlan: f.ServiceVLAN, tpid: EtherTypeServiceVLAN},
		{vlan: f.VLAN, tpid: EtherTypeVLAN},
	}

	n := 12
	for _, vt := range vlans {
		if vt.vlan == nil {
			continue
		}

		binary.BigEndian.PutUint16(b[n:n+2], uint16(vt.tpid))
		if _, err := vt.vlan.read(b[n+2 : n+4]); err != nil {
			return 0, err
		}
		n += 4
	}

	// Marshal actual EtherType after any VLANs, copy payload into
	// output bytes.
	binary.BigEndian.PutUint16(b[n:n+2], uint16(f.EtherType))
	copy(b[n+2:], f.Payload)

	return len(b), nil
}

func (f *Frame) UnmarshalBinary(b []byte) error {
	if len(b) < 14 {
		return io.ErrUnexpectedEOF
	}

	n := 14

	et := EtherType(binary.BigEndian.Uint16(b[n-2 : n]))
	switch et {
	case EtherTypeServiceVLAN, EtherTypeVLAN:
		nn, err := f.unmarshalVLANs(et, b[n:])
		if err != nil {
			return err
		}

		n += nn
	default:
		f.EtherType = et
	}

	bb := make([]byte, 6+6+len(b[n:]))
	copy(bb[0:6], b[0:6])
	f.Destination = bb[0:6]
	copy(bb[6:12], b[6:12])
	f.Source = bb[6:12]

	copy(bb[12:], b[n:])
	f.Payload = bb[12:]

	return nil
}

func (f *Frame) UnmarshalFCS(b []byte) error {
	if len(b) < 4 {
		return io.ErrUnexpectedEOF
	}

	want := binary.BigEndian.Uint32(b[len(b)-4:])
	got := crc32.ChecksumIEEE(b[0 : len(b)-4])
	if want != got {
		return ErrInvalidFCS
	}

	return f.UnmarshalBinary(b[0 : len(b)-4])
}

func (f *Frame) length() int {
	pl := len(f.Payload)
	if pl < minPayload {
		pl = minPayload
	}

	var vlanLen int
	switch {
	case f.ServiceVLAN != nil && f.VLAN != nil:
		vlanLen = 8
	case f.VLAN != nil:
		vlanLen = 4
	}

	// 6 bytes: destination hardware address
	// 6 bytes: source hardware address
	// N bytes: VLAN tags (if present)
	// 2 bytes: EtherType
	// N bytes: payload length (may be padded)
	return 6 + 6 + vlanLen + 2 + pl
}

func (f *Frame) unmarshalVLANs(tpid EtherType, b []byte) (int, error) {
	if len(b) < 4 {
		return 0, io.ErrUnexpectedEOF
	}

	var n int

	switch tpid {
	case EtherTypeServiceVLAN:
		vlan := new(VLAN)
		if err := vlan.UnmarshalBinary(b[n : n+2]); err != nil {
			return 0, err
		}
		f.ServiceVLAN = vlan

		if EtherType(binary.BigEndian.Uint16(b[n+2:n+4])) != EtherTypeVLAN {
			return 0, ErrInvalidVLAN
		}

		n += 4
		if len(b[n:]) < 4 {
			return 0, io.ErrUnexpectedEOF
		}

		fallthrough
	case EtherTypeVLAN:
		vlan := new(VLAN)
		if err := vlan.UnmarshalBinary(b[n : n+2]); err != nil {
			return 0, err
		}

		f.VLAN = vlan
		f.EtherType = EtherType(binary.BigEndian.Uint16(b[n+2 : n+4]))
		n += 4
	default:
		panic(fmt.Sprintf("unknown VLAN TPID: %04x", tpid))
	}

	return n, nil
}
