package ja3

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/sbhamad/tlsx"
)

// DigestPacket returns the Ja3 digest
// for a packet carrying a TLS Client Hello
// or an empty byte slice
func DigestPacket(p gopacket.Packet) [md5.Size]byte {
	return md5.Sum(BarePacket(p))
}

// DigestHexPacket returns the hex string for the packet
// for a packet carrying a TLS Client Hello
func DigestHexPacket(p gopacket.Packet) string {

	bare := BarePacket(p)
	if len(bare) == 0 {
		return ""
	}

	sum := md5.Sum(bare)
	return hex.EncodeToString(sum[:])
}

// BarePacket returns the Ja3 digest if the supplied packet contains a TLS client hello
// otherwise returns an empty string
func BarePacket(p gopacket.Packet) []byte {
	if tl := p.TransportLayer(); tl != nil {
		if tcp, ok := tl.(*layers.TCP); ok {
			if tcp.SYN {
				// Connection setup
			} else if tcp.FIN {
				// Connection teardown
			} else if tcp.ACK && len(tcp.LayerPayload()) == 0 {
				// Acknowledgement packet
			} else if tcp.RST {
				// Unexpected packet
			} else {

				// invalid length, this is not handled by the tsx package
				// bail out otherwise there will be a panic
				if len(tcp.LayerPayload()) < 6 {
					return []byte{}
				}

				// data packet
				var (
					hello = tlsx.ClientHello{}
					err   = hello.Unmarshall(tcp.LayerPayload())
				)
				if err != nil {
					if Debug {
						fmt.Println(err, p.Dump())
					}
					return []byte{}
				}

				// return JA3 bare
				return Bare(&hello)
			}
		}
	}
	return []byte{}
}
