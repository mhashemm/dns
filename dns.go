package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

var supportedTypes = map[uint16]struct{}{
	1:  {},
	2:  {},
	28: {},
	41: {},
}

type resourceRecord struct {
	Name  string `json:"name"`
	Data  string `json:"data"`
	Class uint16 `json:"-"`
	Type  uint16 `json:"type"`
	Ttl   int32  `json:"TTL"`
}

func (rr resourceRecord) WriteTo(buf *bytes.Buffer, nsCache map[string]uint16) {
	b := labelBytes(rr.Name, nsCache, true, uint16(buf.Len()))
	buf.Write(b)
	binary.Write(buf, binary.BigEndian, rr.Type)
	binary.Write(buf, binary.BigEndian, rr.Class)
	binary.Write(buf, binary.BigEndian, rr.Ttl)

	switch rr.Type {
	case 1, 28:
		addr, _ := netip.ParseAddr(rr.Data)
		binary.Write(buf, binary.BigEndian, uint16(addr.BitLen()/8))
		buf.Write(addr.AsSlice())

	case 2:
		b := labelBytes(rr.Data, nsCache, true, uint16(buf.Len()+2)) // offset+2 because of rdcount 2 bytes
		binary.Write(buf, binary.BigEndian, uint16(len(b)))
		buf.Write(b)
	case 41:
		buf.Write([]byte{0, 0})
	}
}

type header struct {
	ID      uint16 `json:"-"`
	Flags   uint16
	QDCOUNT uint16 `json:"-"` // Question Count
	ANCOUNT uint16 `json:"-"` // Answer Count
	NSCOUNT uint16 `json:"-"` // Authority Count
	ARCOUNT uint16 `json:"-"` // Additional Count
}

func (h header) String() string {
	return fmt.Sprintf(
		"QR:%t, OPCODE:%d, AA:%t, TC:%t, RD:%t, RA:%t, Z:%d, RCODE: %d",
		h.QR(),
		h.OPCODE(),
		h.AA(),
		h.TC(),
		h.RD(),
		h.RA(),
		h.Z(),
		h.RCODE(),
	)
}

func (h header) WriteTo(buf *bytes.Buffer) {
	binary.Write(buf, binary.BigEndian, h.ID)
	binary.Write(buf, binary.BigEndian, h.Flags)
	binary.Write(buf, binary.BigEndian, h.QDCOUNT)
	binary.Write(buf, binary.BigEndian, h.ANCOUNT)
	binary.Write(buf, binary.BigEndian, h.NSCOUNT)
	binary.Write(buf, binary.BigEndian, h.ARCOUNT)
}

// Query Response:	1 bit -	0 for queries, 1 for responses.
func (h header) QR() bool {
	return (h.Flags >> 15) == 1
}

func (h *header) SetQR(v uint16) {
	if v > 1 {
		return
	}
	v <<= 15
	if v == 0 {
		h.Flags &= ((^v) >> 1)
	} else {
		h.Flags |= v
	}
}

// Operation Code: 4 bits -	Typically always 0, see RFC1035 for details.
func (h header) OPCODE() uint8 {
	return uint8((h.Flags >> 11) & 0b1111)
}

// Authoritative Answer:	1 bit -	Set to 1 if the responding server is authoritative - that is, it "owns" - the domain queried.
func (h header) AA() bool {
	return ((h.Flags >> 10) & 0b1) == 1
}

// Truncated Message: 1 bit - Set to 1 if the message length exceeds 512 bytes.
// Traditionally a hint that the query can be reissued using TCP, for which the length limitation doesn't apply.
func (h header) TC() bool {
	return ((h.Flags >> 9) & 0b1) == 1
}

// Recursion Desire: 1 bit - Set by the sender of the request if the server should attempt to resolve the query recursively if it does not have an answer readily available.
func (h header) RD() bool {
	return ((h.Flags >> 8) & 0b1) == 1
}

func (h *header) SetRD(v uint16) {
	if v > 1 {
		return
	}
	v <<= 8
	if v == 0 {
		h.Flags &= 0b1111111011111111
	} else {
		h.Flags |= v
	}
}

// Recursion Available: 1 bit -	Set by the server to indicate whether or not recursive queries are allowed.
func (h header) RA() bool {
	return ((h.Flags >> 7) & 0b1) == 1
}

func (h *header) SetRA(v uint16) {
	if v > 1 {
		return
	}
	v <<= 7
	if v == 0 {
		h.Flags &= 0b1111111101111111
	} else {
		h.Flags |= v
	}
}

// Reserved: 3 bits -	Originally reserved for later use, but now used for DNSSEC queries.
func (h header) Z() uint8 {
	return uint8((h.Flags >> 4) & 0b111)
}

// Response Code:	4 bits - Set by the server to indicate the status of the response,
// i.e. whether or not it was successful or failed, and in the latter case providing details about the cause of the failure.
func (h header) RCODE() uint8 {
	return uint8(h.Flags & 0b1111)
}

func (h *header) SetRCODE(v uint16) {
	if v > 15 {
		return
	}
	h.Flags &= (v | 0b1111111111110000)
}

type question struct {
	Name  string `json:"name"`
	Type  uint16 `json:"type"`
	Class uint16 `json:"-"`
}

func (q question) WriteTo(buf *bytes.Buffer, nsCache map[string]uint16) {
	b := labelBytes(q.Name, nsCache, false, uint16(buf.Len()))
	buf.Write(b)
	binary.Write(buf, binary.BigEndian, q.Type)
	binary.Write(buf, binary.BigEndian, q.Class)
}

type message struct {
	Header     header
	Question   []question
	Answer     []resourceRecord
	Authority  []resourceRecord
	Additional []resourceRecord
}

func (m message) Bytes() []byte {
	buf := &bytes.Buffer{}
	nsCache := make(map[string]uint16)
	m.Header.QDCOUNT = uint16(len(m.Question))
	m.Header.ANCOUNT = uint16(len(m.Answer))
	m.Header.NSCOUNT = uint16(len(m.Authority))
	m.Header.ARCOUNT = uint16(len(m.Additional))
	m.Header.WriteTo(buf)
	for _, q := range m.Question {
		q.WriteTo(buf, nsCache)
	}
	for _, rr := range m.Answer {
		rr.WriteTo(buf, nsCache)
	}
	for _, rr := range m.Authority {
		rr.WriteTo(buf, nsCache)
	}
	for _, rr := range m.Additional {
		rr.WriteTo(buf, nsCache)
	}

	return buf.Bytes()
}

func parseMessage(buf []byte) (*message, uint16) {
	m := message{}
	ml := uint16(12)
	m.Header = parseHeader(buf)
	que, l := parseQuestion(12, buf, m.Header.QDCOUNT)
	m.Question = que
	ml += l
	ans, l := parseRRs(ml, buf, m.Header.ANCOUNT)
	m.Answer = ans
	ml += l
	aut, l := parseRRs(ml, buf, m.Header.NSCOUNT)
	m.Authority = aut
	ml += l
	add, l := parseRRs(ml, buf, m.Header.ARCOUNT)
	m.Additional = add
	ml += l

	return &m, ml
}

func parseHeader(buf []byte) header {
	h := header{
		ID:      binary.BigEndian.Uint16(buf[0:2]),
		Flags:   binary.BigEndian.Uint16(buf[2:4]),
		QDCOUNT: binary.BigEndian.Uint16(buf[4:6]),
		ANCOUNT: binary.BigEndian.Uint16(buf[6:8]),
		NSCOUNT: binary.BigEndian.Uint16(buf[8:10]),
		ARCOUNT: binary.BigEndian.Uint16(buf[10:12]),
	}
	return h
}

func parseLabel(from uint16, buf []byte) (string, uint16) {
	label := strings.Builder{}
	ll := from
	for {
		l := uint16(buf[ll])
		ll += 1
		if l == 0 {
			break
		}
		shouldJump := (l >> 6) == 0b11
		if shouldJump {
			pos := binary.BigEndian.Uint16(buf[ll-1:ll+1]) & 0x3fff
			label1, _ := parseLabel(pos, buf)
			label.WriteString(label1)
			ll += 1
			break
		}
		label.Write(buf[ll : ll+l])
		label.WriteByte('.')
		ll += l
	}
	return strings.ToLower(label.String()), ll - from
}

func parseQuestion(from uint16, buf []byte, qdCount uint16) ([]question, uint16) {
	questions := make([]question, qdCount)
	ql := from
	for i := uint16(0); i < qdCount; i++ {
		q := question{}
		label, ll := parseLabel(ql, buf)
		q.Name = label
		ql += ll
		q.Type = binary.BigEndian.Uint16(buf[ql : ql+2])
		ql += 2
		q.Class = binary.BigEndian.Uint16(buf[ql : ql+2])
		ql += 2
		questions[i] = q
	}
	return questions, ql - from
}

func parseRRs(from uint16, buf []byte, count uint16) ([]resourceRecord, uint16) {
	rrs := make([]resourceRecord, 0, count)
	rrl := from
	for i := uint16(0); i < count; i++ {
		rr := resourceRecord{}
		label, ll := parseLabel(rrl, buf)
		rr.Name = label
		rrl += ll
		rr.Type = binary.BigEndian.Uint16(buf[rrl : rrl+2])
		rrl += 2
		rr.Class = binary.BigEndian.Uint16(buf[rrl : rrl+2])
		rrl += 2
		rr.Ttl = int32(binary.BigEndian.Uint32(buf[rrl : rrl+4]))
		rrl += 4
		rdLen := binary.BigEndian.Uint16(buf[rrl : rrl+2])
		rrl += 2
		rr.Data = parseRData(buf, rrl, rdLen, rr.Type)
		rrl += rdLen

		if _, supported := supportedTypes[rr.Type]; !supported {
			continue
		}
		rrs = append(rrs, rr)
	}
	return rrs, rrl - from
}

func parseRData(buf []byte, from uint16, rdLen uint16, rtype uint16) string {
	var data string
	switch rtype {
	case 1, 28: // A, AAAA
		data = net.IP(buf[from : from+rdLen]).String()
	case 2: // NS
		data, _ = parseLabel(from, buf)
	default:
		data = ""
	}
	return data
}

func labelBytes(label string, nsCache map[string]uint16, compress bool, offset uint16) []byte {
	if label == "" {
		return []byte{0}
	}
	if compress {
		pos, cached := nsCache[label]
		if cached {
			return binary.BigEndian.AppendUint16(make([]byte, 0, 2), pos)
		}
	}
	addToNsCache(nsCache, label, offset)
	l := uint16(0)
	parts := strings.Split(label, ".")
	buf := &bytes.Buffer{}
	for _, p := range parts {
		if p == "" {
			// terminator byte
			buf.WriteByte(0)
			break
		}
		binary.Write(buf, binary.BigEndian, uint8(len(p)))
		buf.WriteString(p)
		l += uint16(len(p)) + 1
		s := label[l:]
		if compress {
			pos, cached := nsCache[s]
			if cached {
				binary.Write(buf, binary.BigEndian, pos)
				break
			}
		}
		addToNsCache(nsCache, s, offset+l)
	}
	return buf.Bytes()
}

func addToNsCache(nsCache map[string]uint16, str string, pos uint16) (uint16, bool) {
	if str == "" {
		return 0, false
	}
	cachedPos, exists := nsCache[str]
	// any offset after the header is valid
	if !exists && pos >= 12 {
		cachedPos = pos | 0xc000
		nsCache[str] = cachedPos
		return cachedPos, true
	}
	return cachedPos, exists
}
