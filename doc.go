// SPDX-License-Identifier: GPL-3.0-or-later

// Package dnscodec is a DNS client message parser and serializer.
//
// [NewQuery] and [*Query] allows constructing and packing a DNS query
// message. [ParseResponse] and [*Response] allows unpacking and validating
// a raw DNS query response.
//
// This package does not implement a DNS parser/serializer. We use and
// expose [github.com/miekg/dns] types. The intent is just that of providing
// convenience functions and common response validation algorithms.
package dnscodec
