# DNS Message Parser and Serializer

[![GoDoc](https://pkg.go.dev/badge/github.com/bassosimone/dnscodec)](https://pkg.go.dev/github.com/bassosimone/dnscodec) [![Build Status](https://github.com/bassosimone/dnscodec/actions/workflows/go.yml/badge.svg)](https://github.com/bassosimone/dnscodec/actions) [![codecov](https://codecov.io/gh/bassosimone/dnscodec/branch/main/graph/badge.svg)](https://codecov.io/gh/bassosimone/dnscodec)

Small DNS query/response helpers built on top of
[github.com/miekg/dns](https://github.com/miekg/dns).

This module focuses on:

- constructing DNS query messages with safe defaults;
- validating DNS responses against a query;
- extracting valid answers and common record types.

It does not aim to implement a full DNS parser/serializer. Instead, it wraps
[github.com/miekg/dns](https://github.com/miekg/dns) and provides reusable
utility functions and algorithms.

## Example

```Go
import (
	"log"

	"github.com/bassosimone/dnscodec"
	"github.com/miekg/dns"
)

// Serialize a DNS query for DNS-over-UDP
query := dnscodec.NewQuery("www.example.com", dns.TypeA)
msgQuery, err := query.NewMsg()
if err != nil {
	log.Fatal(err)
}
rawQuery, err := msgQuery.Pack()
if err != nil {
	log.Fatal(err)
}
_ = rawQuery // send using your transport

// Parse a DNS response for the above query
msgResponse := new(dns.Msg)
rawResponse := []byte{} // replace with raw response bytes
if err := msgResponse.Unpack(rawResponse); err != nil {
	log.Fatal(err)
}
resp, err := dnscodec.ParseResponse(msgQuery, msgResponse)
if err != nil {
	log.Fatal(err)
}

// Get all the matching A records in the response
aRecs, err := resp.RecordsA()
if err != nil {
	log.Fatal(err)
}

// Same as above but for AAAA
aaaaRecs, err := resp.RecordsAAAA()
if err != nil {
	log.Fatal(err)
}

// Same as above but for CNAME
cnameRecs, err := resp.RecordsCNAME()
if err != nil {
	log.Fatal(err)
}
```

See [example_test.go](example_test.go) for transport-specific query settings.

## API Sketch

- `NewQuery` constructs a query with safe defaults (random ID, EDNS UDP size).
- `ParseResponse` validates and extracts meaningful RRs.
- `Response.RecordsA`, `Response.RecordsAAAA`, `Response.RecordsCNAME` return the records.

## Installation

```sh
go get github.com/bassosimone/dnscodec
```

## Development

```sh
go test ./...
```

## License

```
SPDX-License-Identifier: GPL-3.0-or-later
```
