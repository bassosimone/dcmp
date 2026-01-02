//
// SPDX-License-Identifier: BSD-3-Clause
//
// Adapted from: https://github.com/ooni/probe-engine/blob/v0.23.0/netx/resolver/decoder.go
// Adapted from: https://github.com/golang/go/blob/go1.21.10/src/net/dnsclient_unix.go
// Adapted from: https://github.com/rbmk-project/rbmk/blob/v0.17.0/pkg/dns/dnscore/response.go
//

package dnscodec

import (
	"errors"

	"github.com/miekg/dns"
)

// Additional errors emitted by [ValidateResponseForQuery].
var (
	// ErrInvalidQuery means that the query does not contain a single question.
	ErrInvalidQuery = errors.New("invalid query")
)

// ValidateResponseForQuery validates a DNS response for a given query.
// On success it returns the single validated question from the query.
func ValidateResponseForQuery(query, resp *dns.Msg) (dns.Question, error) {
	// 1. make sure the message is actually a response
	if !resp.Response {
		return dns.Question{}, ErrInvalidResponse
	}

	// 2. make sure the response ID matches the query ID
	if resp.Id != query.Id {
		return dns.Question{}, ErrInvalidResponse
	}

	// 3. make sure the query and the response contains a question
	if len(query.Question) != 1 {
		return dns.Question{}, ErrInvalidQuery
	}
	if len(resp.Question) != 1 {
		return dns.Question{}, ErrInvalidResponse
	}
	resp0 := resp.Question[0]
	query0 := query.Question[0]

	// 4. make sure the question name is correct
	if !responseEqualASCIIName(resp0.Name, query0.Name) {
		return dns.Question{}, ErrInvalidResponse
	}
	if resp0.Qclass != query0.Qclass {
		return dns.Question{}, ErrInvalidResponse
	}
	if resp0.Qtype != query0.Qtype {
		return dns.Question{}, ErrInvalidResponse
	}
	return query0, nil
}

// SPDX-License-Identifier: BSD-3-Clause
//
// Borrowed from Go src/net package.
func responseEqualASCIIName(x, y string) bool {
	if len(x) != len(y) {
		return false
	}
	for i := 0; i < len(x); i++ {
		a := x[i]
		b := y[i]
		if 'A' <= a && a <= 'Z' {
			a += 0x20
		}
		if 'A' <= b && b <= 'Z' {
			b += 0x20
		}
		if a != b {
			return false
		}
	}
	return true
}

func responseCanonicalName(name string) string {
	return dns.CanonicalName(name)
}

// These error messages use the same suffixes used by the Go standard library.
var (
	// ErrCannotUnmarshalMessage indicates that we cannot unmarshal a DNS message.
	ErrCannotUnmarshalMessage = errors.New("cannot unmarshal DNS message")

	// ErrInvalidResponse means that the response is not a response message
	// or does not contain a single question matching the query.
	ErrInvalidResponse = errors.New("invalid DNS response")

	// ErrNoName indicates that the server response code is NXDOMAIN.
	ErrNoName = errors.New("no such host")

	// ErrServerMisbehaving indicates that the server response code is
	// neither 0, nor NXDOMAIN, nor SERVFAIL.
	ErrServerMisbehaving = errors.New("server misbehaving")

	// ErrServerTemporarilyMisbehaving indicates that the server answer is SERVFAIL.
	//
	// The error message is same as [ErrServerMisbehaving] for compatibility with the
	// Go standard library, which assigns the same error string to both errors.
	ErrServerTemporarilyMisbehaving = errors.New("server misbehaving")

	// ErrNoData indicates that there is no pertinent answer in the response.
	ErrNoData = errors.New("no answer from DNS server")
)

// ResponseErrorFromRCODE maps an RCODE inside a valid DNS response
// to an error string using a suffix compatible with the error strings
// returned by [*net.Resolver].
//
// For example, if a domain does not exist, the error
// will use the "no such host" suffix.
//
// If the RCODE is zero, this function returns nil.
//
// Before invoking this function, make sure the response is valid
// for the request by calling [ValidateResponseForQuery].
func ResponseErrorFromRCODE(resp *dns.Msg) error {
	// 1. handle NXDOMAIN case by mapping it to EAI_NONAME
	if resp.Rcode == dns.RcodeNameError {
		return ErrNoName
	}

	// 2. handle the case of lame referral by mapping it to EAI_NODATA
	if resp.Rcode == dns.RcodeSuccess &&
		!resp.Authoritative &&
		!resp.RecursionAvailable &&
		len(resp.Answer) == 0 {
		return ErrNoData
	}

	// 3. handle any other error by mapping to EAI_FAIL
	if resp.Rcode != dns.RcodeSuccess {
		if resp.Rcode == dns.RcodeServerFailure {
			return ErrServerTemporarilyMisbehaving
		}
		return ErrServerMisbehaving
	}
	return nil
}

// ResponseExtractValidAnswers extracts valid RRs from the response considering
// the DNS question that was asked. Before invoking this function, make sure
// the response is valid using [ValidateResponseForQuery] and it does not contain
// errors using [ResponseErrorFromRCODE].
//
// The list of valid RRs is returned in the same order as they appear
// in the response message. If the response does not contain any valid
// RRs, this function returns [ErrNoData].
func ResponseExtractValidAnswers(q0 dns.Question, resp *dns.Msg) ([]dns.RR, error) {
	// 1. Build CNAME chain starting from the query name.
	// RFC 1034 section 4.3.1 says that "the recursive response to a query
	// will be... The answer to the query, possibly preface by one or more
	// CNAME RRs that specify aliases encountered on the way to an answer."
	//
	// We need to validate that CNAMEs form a proper chain and track all
	// valid names in that chain. We try to be careful and account for the
	// names potentially being not canonicalized in the response.
	validNames := make(map[string]bool)
	validNames[responseCanonicalName(q0.Name)] = true

	currentName := q0.Name
	for _, answer := range resp.Answer {
		if cname, ok := answer.(*dns.CNAME); ok {
			header := cname.Header()
			// CNAME must match the current name in the chain
			if responseEqualASCIIName(currentName, header.Name) && header.Class == q0.Qclass {
				currentName = responseCanonicalName(cname.Target)
				validNames[currentName] = true
			}
		}
	}

	// 2. Build list of valid answers: CNAMEs that are part of the chain,
	// plus any other RRs that match a name in the chain.
	valid := []dns.RR{}
	for _, answer := range resp.Answer {
		header := answer.Header()

		// Check if this RR's name is part of the valid chain
		if !validNames[responseCanonicalName(header.Name)] {
			continue
		}

		// Check class matches
		if q0.Qclass != header.Class {
			continue
		}

		// Note: there may be several RR types for a given query so we
		// should not check for the type here
		valid = append(valid, answer)
	}

	// 3. Handle the case of no valid answers
	if len(valid) < 1 {
		return nil, ErrNoData
	}

	// 4. Return the list.
	return valid, nil
}

// Response is a DNS response.
//
// Construct a new instance using [ParseResponse].
type Response struct {
	// Query is the original query message.
	Query *dns.Msg

	// Response is the response message.
	Response *dns.Msg

	// ValidRRs contains the valid RRs for the query.
	ValidRRs []dns.RR
}

// ParseResponse returns a [*Response] given a query and response messages or an
// error if the two response message is not valid for the query.
func ParseResponse(query *dns.Msg, resp *dns.Msg) (*Response, error) {
	q0, err := ValidateResponseForQuery(query, resp)
	if err != nil {
		return nil, err
	}

	if err := ResponseErrorFromRCODE(resp); err != nil {
		return nil, err
	}

	rrs, err := ResponseExtractValidAnswers(q0, resp)
	if err != nil {
		return nil, err
	}

	rp := &Response{
		Query:    query,
		Response: resp,
		ValidRRs: rrs,
	}
	return rp, nil
}

// RecordsA returns all the A records in the response.
func (r *Response) RecordsA() ([]string, error) {
	out := make([]string, 0, len(r.ValidRRs))
	for _, rr := range r.ValidRRs {
		switch rr := rr.(type) {
		case *dns.A:
			out = append(out, rr.A.String())
		}
	}
	if len(out) < 1 {
		return nil, ErrNoData
	}
	return out, nil
}

// RecordsAAAA returns all the AAAA records in the response.
func (r *Response) RecordsAAAA() ([]string, error) {
	out := make([]string, 0, len(r.ValidRRs))
	for _, rr := range r.ValidRRs {
		switch rr := rr.(type) {
		case *dns.AAAA:
			out = append(out, rr.AAAA.String())
		}
	}
	if len(out) < 1 {
		return nil, ErrNoData
	}
	return out, nil
}

// RecordFirstCNAME returns the first CNAME in the response.
func (r *Response) RecordFirstCNAME() (string, error) {
	for _, rr := range r.ValidRRs {
		switch rr := rr.(type) {
		case *dns.CNAME:
			return rr.Target, nil
		}
	}
	return "", ErrNoData
}
