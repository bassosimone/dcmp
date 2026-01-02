//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Adapted from: https://github.com/rbmk-project/rbmk/blob/v0.17.0/pkg/dns/dnscore/response_test.go
//

package dnscodec

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestValidateResponseForQuery(t *testing.T) {
	tests := []struct {
		name     string
		modify   func(*dns.Msg, *dns.Msg)
		expected error
	}{
		{
			name: "ValidResponse",
			modify: func(query, resp *dns.Msg) {
				// No modification needed, valid response.
			},
			expected: nil,
		},

		{
			name: "InvalidResponseID",
			modify: func(query, resp *dns.Msg) {
				resp.Id = query.Id + 1
			},
			expected: ErrInvalidResponse,
		},

		{
			name: "InvalidResponseNotAResponse",
			modify: func(query, resp *dns.Msg) {
				resp.Response = false
			},
			expected: ErrInvalidResponse,
		},

		{
			name: "InvalidQueryNoQuestion",
			modify: func(query, resp *dns.Msg) {
				query.Question = nil
			},
			expected: ErrInvalidQuery,
		},

		{
			name: "InvalidResponseNoQuestion",
			modify: func(query, resp *dns.Msg) {
				resp.Question = nil
			},
			expected: ErrInvalidResponse,
		},

		{
			name: "InvalidResponseQuestionName",
			modify: func(query, resp *dns.Msg) {
				resp.Question[0].Name = "invalid.com."
			},
			expected: ErrInvalidResponse,
		},

		{
			name: "InvalidResponseQuestionClass",
			modify: func(query, resp *dns.Msg) {
				resp.Question[0].Qclass = dns.ClassCHAOS
			},
			expected: ErrInvalidResponse,
		},

		{
			name: "InvalidResponseQuestionType",
			modify: func(query, resp *dns.Msg) {
				resp.Question[0].Qtype = dns.TypeAAAA
			},
			expected: ErrInvalidResponse,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query := new(dns.Msg)
			query.SetQuestion("example.com.", dns.TypeA)

			resp := new(dns.Msg)
			resp.SetReply(query)

			tt.modify(query, resp)

			q0, err := ValidateResponseForQuery(query, resp)
			if tt.expected != nil {
				require.ErrorIs(t, err, tt.expected)
				return
			}
			require.NoError(t, err)
			require.Equal(t, query.Question[0], q0)
		})
	}
}

func TestResponseEqualASCIIName(t *testing.T) {
	tests := []struct {
		name     string
		x        string
		y        string
		expected bool
	}{
		{"EqualNames", "example.com.", "example.com.", true},
		{"EqualNamesDifferentCase", "Example.COM.", "exaMple.com.", true},
		{"DifferentNames", "example.com.", "example.org.", false},
		{"DifferentLengths", "example.com.", "example.co.uk.", false},
		{"OnlyPrefixMatch", "example.co.", "example.co.uk.", false},
		{"EmptyStrings", "", "", true},
		{"OneEmptyString", "example.com.", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := responseEqualASCIIName(tt.x, tt.y)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestResponseErrorFromRCODE(t *testing.T) {
	tests := []struct {
		name     string
		rcode    int
		expected error
	}{
		{"NameError", dns.RcodeNameError, ErrNoName},
		{"ServerFailure", dns.RcodeServerFailure, ErrServerTemporarilyMisbehaving},
		{"LameReferral", dns.RcodeSuccess, ErrNoData},
		{"Success", dns.RcodeSuccess, nil},
		{"Refused", dns.RcodeRefused, ErrServerMisbehaving},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := new(dns.Msg)
			resp.Rcode = tt.rcode

			switch tt.name {
			case "LameReferral":
				resp.Authoritative = false
				resp.RecursionAvailable = false
				resp.Answer = nil

			case "Success":
				resp.Authoritative = true
				resp.RecursionAvailable = true
				resp.Answer = []dns.RR{&dns.A{
					Hdr: dns.RR_Header{
						Name:   "example.com.",
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
					},
					A: net.IPv4(127, 0, 0, 1),
				}}
			}

			err := ResponseErrorFromRCODE(resp)
			if tt.expected != nil {
				require.ErrorIs(t, err, tt.expected)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestResponseExtractValidAnswers(t *testing.T) {
	tests := []struct {
		name     string
		query    *dns.Msg
		resp     *dns.Msg
		expected int
		err      error
	}{
		{
			name: "ValidAnswerWithoutCNAME",
			query: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeA)
				return m
			}(),
			resp: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetReply(new(dns.Msg))
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{
						Name:   "example.com.",
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
					},
					A: net.IPv4(127, 0, 0, 1),
				})
				return m
			}(),
			expected: 1,
			err:      nil,
		},

		{
			name: "ValidAnswerWithCNAME",
			query: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.co.uk.", dns.TypeA)
				return m
			}(),
			resp: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetReply(new(dns.Msg))
				m.Answer = append(m.Answer, &dns.CNAME{
					Hdr: dns.RR_Header{
						Name:   "example.co.uk.",
						Rrtype: dns.TypeCNAME,
						Class:  dns.ClassINET,
					},
					Target: "example.com.",
				})
				m.Answer = append(m.Answer, &dns.CNAME{
					Hdr: dns.RR_Header{
						Name:   "example.com.",
						Rrtype: dns.TypeCNAME,
						Class:  dns.ClassINET,
					},
					Target: "example.org.",
				})
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{
						Name:   "example.org.",
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
					},
					A: net.IPv4(127, 0, 0, 1),
				})
				return m
			}(),
			expected: 3,
			err:      nil,
		},
		{
			name: "ValidAnswerWithCNAMEMixedCase",
			query: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("Example.CO.UK.", dns.TypeA)
				return m
			}(),
			resp: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetReply(new(dns.Msg))
				m.Answer = append(m.Answer, &dns.CNAME{
					Hdr: dns.RR_Header{
						Name:   "eXample.co.uk.",
						Rrtype: dns.TypeCNAME,
						Class:  dns.ClassINET,
					},
					Target: "ExamPle.com.",
				})
				m.Answer = append(m.Answer, &dns.CNAME{
					Hdr: dns.RR_Header{
						Name:   "example.COM.",
						Rrtype: dns.TypeCNAME,
						Class:  dns.ClassINET,
					},
					Target: "Example.ORG.",
				})
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{
						Name:   "eXaMpLe.org.",
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
					},
					A: net.IPv4(127, 0, 0, 1),
				})
				return m
			}(),
			expected: 3,
			err:      nil,
		},

		{
			name: "NoAnswers",
			query: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeA)
				return m
			}(),
			resp: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetReply(new(dns.Msg))
				return m
			}(),
			expected: 0,
			err:      ErrNoData,
		},

		{
			name: "MismatchedName",
			query: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeA)
				return m
			}(),
			resp: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetReply(new(dns.Msg))
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{
						Name:   "example.org.",
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
					},
					A: net.IPv4(127, 0, 0, 1),
				})
				return m
			}(),
			expected: 0,
			err:      ErrNoData,
		},

		{
			name: "MismatchedClass",
			query: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeA)
				return m
			}(),
			resp: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetReply(new(dns.Msg))
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{
						Name:   "example.com.",
						Rrtype: dns.TypeA,
						Class:  dns.ClassCHAOS,
					},
					A: net.IPv4(127, 0, 0, 1),
				})
				return m
			}(),
			expected: 0,
			err:      ErrNoData,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			answers, err := ResponseExtractValidAnswers(tt.query.Question[0], tt.resp)
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
				require.Len(t, answers, 0)
				return
			}
			require.NoError(t, err)
			require.Len(t, answers, tt.expected)
		})
	}
}
