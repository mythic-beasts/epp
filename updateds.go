package epp

import (
	"bytes"
	"encoding/xml"
	"fmt"

	//	"github.com/nbio/xx"
)

type DSRecord struct {
	KeyTag     int
	Algorithm  int
	DigestType int
	Digest     string
}

// CheckDomain queries the EPP server for the availability status of one or more domains.
func (c *Conn) DomainUpdateDS(domain string, add []DSRecord, rem []DSRecord) (*DomainUpdateResponse, error) {
	err := encodeDomainUpdateDS(&c.buf, domain, add, rem)
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
	return &res.DomainUpdateResponse, nil
}

func encodeDomainUpdateDS(buf *bytes.Buffer, domain string, add []DSRecord, rem []DSRecord) error {
	buf.Reset()
	buf.WriteString(xmlCommandPrefix)
	buf.WriteString(`<update>`)
	buf.WriteString(`<domain:update xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">`)
	buf.WriteString(`<domain:name>`)
	xml.EscapeText(buf, []byte(domain))
	buf.WriteString(`</domain:name>`)

	buf.WriteString(`</domain:update>`)
	buf.WriteString(`</update>`)
	buf.WriteString(`<extension>`)
	buf.WriteString(`<secDNS:update xmlns:secDNS="urn:ietf:params:xml:ns:secDNS-1.1">`)
	if len(rem) > 0 {
		buf.WriteString(`<secDNS:rem>`)
		for _, dsr := range rem {
			buf.WriteString(`<secDNS:dsData>`)
			buf.WriteString(fmt.Sprintf(`<secDNS:keyTag>%d</secDNS:keyTag>`, dsr.KeyTag))
			buf.WriteString(fmt.Sprintf(`<secDNS:alg>%d</secDNS:alg>`, dsr.Algorithm))
			buf.WriteString(fmt.Sprintf(`<secDNS:digestType>%d</secDNS:digestType>`, dsr.DigestType))
			buf.WriteString(fmt.Sprintf(`<secDNS:digest>%s</secDNS:digest>`, dsr.Digest))
			buf.WriteString(`</secDNS:dsData>`)
		}
		buf.WriteString(`</secDNS:rem>`)
	}
	if len(add) > 0 {
		buf.WriteString(`<secDNS:add>`)
		for _, dsr := range add {
			buf.WriteString(`<secDNS:dsData>`)
			buf.WriteString(fmt.Sprintf(`<secDNS:keyTag>%d</secDNS:keyTag>`, dsr.KeyTag))
			buf.WriteString(fmt.Sprintf(`<secDNS:alg>%d</secDNS:alg>`, dsr.Algorithm))
			buf.WriteString(fmt.Sprintf(`<secDNS:digestType>%d</secDNS:digestType>`, dsr.DigestType))
			buf.WriteString(fmt.Sprintf(`<secDNS:digest>%s</secDNS:digest>`, dsr.Digest))
			buf.WriteString(`</secDNS:dsData>`)
		}
		buf.WriteString(`</secDNS:add>`)
	}
	buf.WriteString(`</secDNS:update>`)
	buf.WriteString(`</extension>`)

	buf.WriteString(xmlCommandSuffix)
	return nil
}

type DomainUpdateResponse struct {
}

func init() {
	// Default EPP check data
	//path := "epp > response > resData > " + ObjDomain + " infData"
}
