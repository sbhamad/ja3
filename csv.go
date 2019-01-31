package ja3

import (
	"fmt"
	"io"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ReadFileCSV reads the PCAP file at the given path
// and prints out all packets containing JA3 digests to the supplied io.Writer
func ReadFileCSV(file string, out io.Writer, separator string) {

	r, f, err := openPcap(file)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	columns := []string{"timestamp", "source_ip", "source_port", "destination_ip", "destination_port", "ja3_digest"}
	out.Write([]byte(strings.Join(columns, separator) + "\n"))

	count := 0
	for {
		// read packet data
		data, ci, err := r.ReadPacketData()
		if err == io.EOF {
			if Debug {
				fmt.Println(count, "fingeprints.")
			}
			return
		} else if err != nil {
			panic(err)
		}

		var (
			// create gopacket
			p = gopacket.NewPacket(data, layers.LinkTypeEthernet, gopacket.Lazy)
			// get JA3 if possible
			digest = DigestHexPacket(p)
		)

		// check if we got a result
		if digest != "" {

			count++

			var (
				b  strings.Builder
				nl = p.NetworkLayer()
				tl = p.TransportLayer()
			)

			// got an a digest but no transport or network layer
			if tl == nil || nl == nil {
				if Debug {
					fmt.Println("got a nil layer: ", nl, tl, p.Dump(), digest)
				}
				continue
			}

			b.WriteString(timeToString(ci.Timestamp))
			b.WriteString(separator)
			b.WriteString(nl.NetworkFlow().Src().String())
			b.WriteString(separator)
			b.WriteString(tl.TransportFlow().Src().String())
			b.WriteString(separator)
			b.WriteString(nl.NetworkFlow().Dst().String())
			b.WriteString(separator)
			b.WriteString(tl.TransportFlow().Dst().String())
			b.WriteString(separator)
			b.WriteString(digest)
			b.WriteString("\n")

			_, err := out.Write([]byte(b.String()))
			if err != nil {
				panic(err)
			}
		}
	}
}
