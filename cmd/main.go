package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/sbhamad/ja3"
)

var (
	flagJSON      = flag.Bool("json", true, "print as JSON array")
	flagCSV       = flag.Bool("csv", false, "print as CSV")
	flagTSV       = flag.Bool("tsv", false, "print as TAB separated values")
	flagSeparator = flag.String("separator", ",", "set a custom separator")
	flagInput     = flag.String("read", "", "read PCAP file")
	flagDebug     = flag.Bool("debug", false, "toggle debug mode")
	flagInterface = flag.String("iface", "", "specify network interface to read packets from")
)

func main() {

	flag.Parse()

	ja3.Debug = *flagDebug

	if *flagInterface != "" {
		ja3.ReadInterfaceCSV(*flagInterface, os.Stdout, *flagSeparator)
		return
	}

	if *flagInput == "" {
		fmt.Println("use the -read flag to supply an input file.")
		os.Exit(1)
	}

	if *flagTSV {
		ja3.ReadFileCSV(*flagInput, os.Stdout, "\t")
		return
	}

	if *flagCSV {
		ja3.ReadFileCSV(*flagInput, os.Stdout, *flagSeparator)
		return
	}

	if *flagJSON {
		ja3.ReadFileJSON(*flagInput, os.Stdout)
	}
}
