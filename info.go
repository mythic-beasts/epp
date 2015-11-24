package epp

import (
	"bytes"
	"encoding/xml"
	"strconv"

	"github.com/nbio/xx"
)

// CheckDomain queries the EPP server for the availability status of one or more domains.
func (c *Conn) DomainInfo(domain string) (*DomainInfoResponse, error) {
	err := encodeDomainInfo(&c.buf, domain)
	if err != nil {
		return nil, err
	}
	err = c.flushDataUnit()
	if err != nil {
		return nil, err
	}
	var res response_
	err = c.readResponse(&res)
	if err != nil {
		return nil, err
	}
	return &res.DomainInfoResponse, nil
}

func encodeDomainInfo(buf *bytes.Buffer, domain string) error {
	buf.Reset()
	buf.WriteString(xmlCommandPrefix)
	buf.WriteString(`<info>`)
	buf.WriteString(`<domain:info xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">`)
	buf.WriteString(`<domain:name>`)
	xml.EscapeText(buf, []byte(domain))
	buf.WriteString(`</domain:name>`)

	buf.WriteString(`</domain:info>`)
	buf.WriteString(`</info>`)

	buf.WriteString(xmlCommandSuffix)
	return nil
}

type DomainInfoResponse struct {
	Nameservers []string
	Expiry      string
	DSRecords   []DSRecord
}

func init() {
	// Default EPP check data
	path := "epp > response > resData > " + ObjDomain + " infData"
	scanResponse.MustHandleCharData(path+"> ns > hostObj", func(c *xx.Context) error {
		di := &c.Value.(*response_).DomainInfoResponse
		di.Nameservers = append(di.Nameservers, string(c.CharData))
		return nil
	})
	scanResponse.MustHandleCharData(path+">exDate", func(c *xx.Context) error {
		c.Value.(*response_).DomainInfoResponse.Expiry = string(c.CharData)
		return nil
	})

	path = "epp > response > extension > urn:ietf:params:xml:ns:secDNS-1.1 infData"
	scanResponse.MustHandleStartElement(path+">dsData", func(c *xx.Context) error {
		dsd := &c.Value.(*response_).DomainInfoResponse
		dsd.DSRecords = append(dsd.DSRecords, DSRecord{})
		return nil
	})

	scanResponse.MustHandleCharData(path+">dsData>keyTag", func(c *xx.Context) error {
		dsrecords := c.Value.(*response_).DomainInfoResponse.DSRecords
		dsrecords[len(dsrecords)-1].KeyTag, _ = strconv.Atoi(string(c.CharData))
		return nil
	})

	scanResponse.MustHandleCharData(path+">dsData>alg", func(c *xx.Context) error {
		dsrecords := c.Value.(*response_).DomainInfoResponse.DSRecords
		dsrecords[len(dsrecords)-1].Algorithm, _ = strconv.Atoi(string(c.CharData))
		return nil
	})

	scanResponse.MustHandleCharData(path+">dsData>digestType", func(c *xx.Context) error {
		dsrecords := c.Value.(*response_).DomainInfoResponse.DSRecords
		dsrecords[len(dsrecords)-1].DigestType, _ = strconv.Atoi(string(c.CharData))
		return nil
	})

	scanResponse.MustHandleCharData(path+">dsData>digest", func(c *xx.Context) error {
		dsrecords := c.Value.(*response_).DomainInfoResponse.DSRecords
		dsrecords[len(dsrecords)-1].Digest = string(c.CharData)
		return nil
	})
}
