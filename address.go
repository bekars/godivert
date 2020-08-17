package godivert

import "fmt"

// Represents a WinDivertAddress struct
// See : https://reqrypt.org/windivert-doc.html#divert_address
// As go doesn't not support bit fields
// we use a little trick to get the Direction, Loopback, Import and PseudoChecksum fields
// Only support network and network_forward layer for now
type WinDivertAddress struct {
	Timestamp int64
	Flags     uint64
	IfIdx     uint32
	SubIfIdx  uint32
}

func (w *WinDivertAddress) String() string {
	return fmt.Sprintf("{\n"+
		"\t\tTimestamp=%d\n"+
		"\t\tInteface={IfIdx=%d SubIfIdx=%d}\n"+
		"\t\tDirection=%v\n"+
		"\t\tLoopback=%t\n"+
		"\t\tImpostor=%t\n"+
		"\t\tValidChecksum={IP=%t TCP=%t UDP=%t}\n"+
		"\t}",
		w.Timestamp, w.IfIdx, w.SubIfIdx, w.Direction(), w.Loopback(), w.Impostor(),
		w.ValidIPChecksum(), w.ValidTCPChecksum(), w.ValidUDPChecksum())
}

// Returns the direction of the packet
// WinDivertDirectionInbound (true) for inbounds packets
// WinDivertDirectionOutbounds (false) for outbounds packets
func (w *WinDivertAddress) Direction() Direction {
	return Direction((w.Flags>>17)&0x1 == 0)
}

func (w *WinDivertAddress) SetDirection(d int) {
	w.Flags = w.Flags&(uint64(0)<<17) | (uint64(d) << 17)
}

// Returns true if the packet is a loopback packet
func (w *WinDivertAddress) Loopback() bool {
	return (w.Flags>>18)&0x1 == 1
}

// Returns true if the packet is an impostor
// See https://reqrypt.org/windivert-doc.html#divert_address for more information
func (w *WinDivertAddress) Impostor() bool {
	return (w.Flags>>19)&0x1 == 1
}

func (w *WinDivertAddress) IPv6() bool {
	return (w.Flags>>20)&0x1 == 1
}

// Returns true if the packet uses a Valid IP checksum
func (w *WinDivertAddress) ValidIPChecksum() bool {
	return (w.Flags>>21)&0x1 == 1
}

// Returns true if the packet uses a Valid TCP checksum
func (w *WinDivertAddress) ValidTCPChecksum() bool {
	return (w.Flags>>22)&0x1 == 1
}

// Returns true if the packet uses a Valid UDP checksum
func (w *WinDivertAddress) ValidUDPChecksum() bool {
	return (w.Flags>>23)&0x1 == 1
}
