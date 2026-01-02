// SPDX-License-Identifier: GPL-3.0-or-later

package dnscodec_test

import (
	"fmt"

	"github.com/bassosimone/dnscodec"
	"github.com/bassosimone/runtimex"
	"github.com/miekg/dns"
)

// Use deterministic query ID to have deterministic output.
//
// In production you should use [dns.Id].
func randomQueryID() uint16 {
	return 37
}

func Example_generateQueryForUDP() {
	query := dnscodec.NewQuery("www.example.com", dns.TypeA)
	query.ID = randomQueryID()
	msg := runtimex.PanicOnError1(query.NewMsg())
	fmt.Printf("%s\n", msg.String())

	// Output:
	//
	// ;; opcode: QUERY, status: NOERROR, id: 37
	// ;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1
	//
	// ;; OPT PSEUDOSECTION:
	// ; EDNS: version 0; flags:; udp: 1232
	//
	// ;; QUESTION SECTION:
	// ;www.example.com.	IN	 A
}

func Example_generateQueryForTCP() {
	query := dnscodec.NewQuery("www.example.com", dns.TypeA)
	query.ID = randomQueryID()
	query.MaxSize = dnscodec.QueryMaxResponseSizeTCP
	msg := runtimex.PanicOnError1(query.NewMsg())
	fmt.Printf("%s\n", msg.String())

	// Output:
	//
	// ;; opcode: QUERY, status: NOERROR, id: 37
	// ;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1
	//
	// ;; OPT PSEUDOSECTION:
	// ; EDNS: version 0; flags:; udp: 4096
	//
	// ;; QUESTION SECTION:
	// ;www.example.com.	IN	 A
}

func Example_generateQueryForTLS() {
	query := dnscodec.NewQuery("www.example.com", dns.TypeA)
	query.ID = randomQueryID()
	query.Flags = dnscodec.QueryFlagBlockLengthPadding | dnscodec.QueryFlagDNSSec
	query.MaxSize = dnscodec.QueryMaxResponseSizeTCP
	msg := runtimex.PanicOnError1(query.NewMsg())
	fmt.Printf("%s\n", msg.String())

	// Output:
	//
	// ;; opcode: QUERY, status: NOERROR, id: 37
	// ;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1
	//
	// ;; OPT PSEUDOSECTION:
	// ; EDNS: version 0; flags: do; udp: 4096
	// ; PADDING: 0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
	//
	// ;; QUESTION SECTION:
	// ;www.example.com.	IN	 A
}

func Example_generateQueryForHTTPS() {
	query := dnscodec.NewQuery("www.example.com", dns.TypeA)
	query.ID = 0
	query.Flags = dnscodec.QueryFlagBlockLengthPadding | dnscodec.QueryFlagDNSSec
	query.MaxSize = dnscodec.QueryMaxResponseSizeTCP
	msg := runtimex.PanicOnError1(query.NewMsg())
	fmt.Printf("%s\n", msg.String())

	// Output:
	//
	// ;; opcode: QUERY, status: NOERROR, id: 0
	// ;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1
	//
	// ;; OPT PSEUDOSECTION:
	// ; EDNS: version 0; flags: do; udp: 4096
	// ; PADDING: 0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
	//
	// ;; QUESTION SECTION:
	// ;www.example.com.	IN	 A
}

func Example_generateQueryForQUIC() {
	query := dnscodec.NewQuery("www.example.com", dns.TypeA)
	query.ID = 0
	query.Flags = dnscodec.QueryFlagBlockLengthPadding | dnscodec.QueryFlagDNSSec
	query.MaxSize = dnscodec.QueryMaxResponseSizeTCP
	msg := runtimex.PanicOnError1(query.NewMsg())
	fmt.Printf("%s\n", msg.String())

	// Output:
	//
	// ;; opcode: QUERY, status: NOERROR, id: 0
	// ;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1
	//
	// ;; OPT PSEUDOSECTION:
	// ; EDNS: version 0; flags: do; udp: 4096
	// ; PADDING: 0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
	//
	// ;; QUESTION SECTION:
	// ;www.example.com.	IN	 A
}
