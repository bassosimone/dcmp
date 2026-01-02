// SPDX-License-Identifier: BSD-3-Clause

package dnscodec

import (
	"testing"

	"github.com/bassosimone/runtimex"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestQueryClone(t *testing.T) {
	query := &Query{
		Name:    "www.example.com",
		Type:    dns.TypeA,
		Flags:   QueryFlagBlockLengthPadding | QueryFlagDNSSec,
		ID:      1234,
		MaxSize: QueryMaxResponseSizeTCP,
	}

	clone := query.Clone()

	require.NotSame(t, query, clone)
	require.Equal(t, query, clone)

	clone.Name = "www.example.net"
	clone.Type = dns.TypeAAAA
	clone.Flags = 0
	clone.ID = 5678
	clone.MaxSize = QueryMaxResponseSizeUDP

	require.Equal(t, "www.example.com", query.Name)
	require.Equal(t, dns.TypeA, query.Type)
	require.Equal(t, uint16(QueryFlagBlockLengthPadding|QueryFlagDNSSec), query.Flags)
	require.Equal(t, uint16(1234), query.ID)
	require.Equal(t, uint16(QueryMaxResponseSizeTCP), query.MaxSize)
}

func TestQueryNewMsgIDNA(t *testing.T) {
	query := &Query{
		Name:    "bücher.example",
		Type:    dns.TypeA,
		ID:      42,
		MaxSize: QueryMaxResponseSizeUDP,
	}

	msg, err := query.NewMsg()
	require.NoError(t, err)
	require.Len(t, msg.Question, 1)
	require.Equal(t, "xn--bcher-kva.example.", msg.Question[0].Name)
}

func TestQueryNewMsgIDNAError(t *testing.T) {
	query := &Query{
		Name: "bad name.example",
		Type: dns.TypeA,
	}

	_, err := query.NewMsg()
	require.Error(t, err)
}

func TestQueryNewMsgPadding(t *testing.T) {
	query := NewQuery("www.example.com", dns.TypeA)
	query.ID = 1

	msgBase := runtimex.PanicOnError1(query.NewMsg())
	rawBase := runtimex.PanicOnError1(msgBase.Pack())
	baseLen := len(rawBase)

	queryPad := query.Clone()
	queryPad.Flags |= QueryFlagBlockLengthPadding
	msgPad := runtimex.PanicOnError1(queryPad.NewMsg())
	rawPad := runtimex.PanicOnError1(msgPad.Pack())

	expectedPadding := int((128 - uint16(baseLen+4)) % 128)

	var pad *dns.EDNS0_PADDING
	for _, opt := range msgPad.IsEdns0().Option {
		if p, ok := opt.(*dns.EDNS0_PADDING); ok {
			pad = p
			break
		}
	}
	require.NotNil(t, pad)
	require.Len(t, pad.Padding, expectedPadding)
	require.Equal(t, baseLen+4+expectedPadding, len(rawPad))
	require.Equal(t, 0, len(rawPad)%128)
}
