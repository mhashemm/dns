package main

import (
	"fmt"
	"math/rand"
	"net"
	"net/netip"
)

func resolve(q question, rd bool) (*message, error) {
	m, cached := answerCache.Get(q.Name)
	if cached {
		return m, nil
	}
	tld, isTld := topLevelDomain(q.Name)
	m, err := resolveTopLevelDomain(tld)
	if err != nil {
		return nil, err
	}
	if isTld || !rd {
		return m, nil
	}
	owner := m.Authority[rand.Intn(len(m.Authority))]
	ownerRRs, exists := root.Zones[owner.Data].RRs[q.Type]
	if !exists {
		return nil, fmt.Errorf("%s with type %d: doesn't exists", owner.Name, q.Type)
	}
	owner = ownerRRs[rand.Intn(len(ownerRRs))]

	m, err = ask(owner.Data, q, true, 0)
	if err != nil {
		return nil, err
	}

	answerCache.Add(q.Name, m.Answer)

	return m, nil
}

func resolveTopLevelDomain(tld string) (*message, error) {
	zone, exists := root.Zones[tld]
	if !exists {
		return nil, fmt.Errorf("%s: doesn't exists", tld)
	}
	m := &message{}
	m.Authority = append(m.Authority, zone.RRs[2]...)
	for _, rr := range zone.RRs[2] {
		authZone, exists := root.Zones[rr.Data]
		if !exists {
			continue
		}
		m.Additional = append(m.Additional, authZone.RRs[1]...)
		m.Additional = append(m.Additional, authZone.RRs[28]...)
	}
	return m, nil
}

func ask(addr string, q question, rd bool, depth int) (*message, error) {
	if depth >= 69 {
		return nil, fmt.Errorf("%s: reached max recursive depth", q.Name)
	}
	h := header{
		ID: uint16(rand.Int31n(65536)),
	}
	h.SetQR(0)
	if rd {
		h.SetRD(1)
	}
	m := &message{
		Header:   h,
		Question: []question{q},
	}

	res, err := request(addr, m.Bytes())
	if err != nil {
		return nil, err
	}

	m, _ = parseMessage(res)
	if !rd || len(m.Answer) > 0 || len(m.Authority) <= 0 {
		return m, nil
	}

	auth := m.Authority[rand.Intn(len(m.Authority))]
	foundInAR := false
	for _, rr := range m.Additional {
		if rr.Name == auth.Data && rr.Type == 1 {
			auth = rr
			foundInAR = true
			break
		}
	}

	if !foundInAR {
		q := question{
			Name:  auth.Data,
			Type:  1,
			Class: 1,
		}
		m, err = resolve(q, true)
		if err != nil {
			return nil, err
		}
		if m.Header.ANCOUNT == 0 {
			return nil, fmt.Errorf("%s: can't resolve", auth.Data)
		}
		auth = m.Answer[0]
	}

	m, err = ask(auth.Data, q, rd, depth+1)

	return m, err
}

func request(addr string, payload []byte) ([]byte, error) {
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return nil, err
	}
	remote := &net.UDPAddr{
		IP:   ip.AsSlice(),
		Port: 53,
	}
	conn, err := net.DialUDP("udp", nil, remote)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.Write(payload)
	received := make([]byte, 1024)
	_, err = conn.Read(received)
	if err != nil {
		return nil, err
	}
	return received, nil
}

func topLevelDomain(domain string) (string, bool) {
	for i := len(domain) - 2; i >= 0; i-- {
		if domain[i] == '.' {
			return domain[i+1:], false
		}
	}
	return domain, true
}
