package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
)

var answerCache = cache{
	cache: make(map[string][]cachedRR),
	mutex: &sync.Mutex{},
}

func main() {

	file, err := os.OpenFile("root.zone.txt", os.O_RDONLY, 0400)
	if err != nil {
		panic(err)
	}
	ParseRoot(file)
	file.Close()

	wg := &sync.WaitGroup{}
	wg.Add(2)

	c := context.Background()

	go udpServer(wg, c)
	go httpServer(wg)

	wg.Wait()
}

func udpServer(wg *sync.WaitGroup, c context.Context) {
	defer wg.Done()
	udpPort, err := strconv.ParseInt(os.Getenv("UDP_PORT"), 10, 32)
	if err != nil {
		panic(err)
	}

	server, err := net.ListenUDP("udp", &net.UDPAddr{Port: int(udpPort)})
	if err != nil {
		panic(err)
	}
	defer server.Close()

	for {
		if c.Err() != nil {
			break
		}
		buf := make([]byte, 1024)
		_, addr, err := server.ReadFrom(buf)
		if err != nil {
			continue
		}
		go udpHandler(server, addr, buf)
	}
}

func httpServer(wg *sync.WaitGroup) {
	defer wg.Done()
	tcpPort, err := strconv.ParseInt(os.Getenv("TCP_PORT"), 10, 32)
	if err != nil {
		panic(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", httpHandler)
	addr := fmt.Sprintf(":%d", tcpPort)
	err = http.ListenAndServe(addr, mux)
	if err != nil {
		panic(err)
	}
}

type responseMessage struct {
	Status     uint8
	TC         bool
	RD         bool
	RA         bool
	Question   []question
	Answer     []resourceRecord `json:",omitempty"`
	Authority  []resourceRecord `json:",omitempty"`
	Additional []resourceRecord `json:",omitempty"`
}

func httpHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !strings.HasPrefix(r.Header.Get("Accept"), "application/dns") {
		w.WriteHeader(http.StatusUnsupportedMediaType)
		return
	}
	rq := r.URL.Query()
	domain := rq.Get("name")
	if domain[len(domain)-1] != '.' {
		domain += "."
	}
	qtype := uint16(1)
	rqt := rq.Get("type")
	qtype, supported := RRTypes[rqt]
	if !supported {
		if rqt != "" {
			w.WriteHeader(http.StatusUnprocessableEntity)
			return
		}
		qtype = 1
	}
	h := header{
		QDCOUNT: 1,
	}
	h.SetRD(1)

	q := question{
		Name:  domain,
		Type:  qtype,
		Class: 1,
	}
	m := &message{
		Header:   h,
		Question: []question{q},
	}
	handler(m)
	w.WriteHeader(http.StatusOK)
	resMsg := responseMessage{
		Status:     m.Header.RCODE(),
		TC:         m.Header.TC(),
		RD:         m.Header.RD(),
		RA:         m.Header.RA(),
		Question:   m.Question,
		Answer:     m.Answer,
		Authority:  m.Authority,
		Additional: m.Additional,
	}
	res, err := json.Marshal(resMsg)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Write(res)
}

func udpHandler(server net.PacketConn, addr net.Addr, buf []byte) {
	m, _ := parseMessage(buf)
	handler(m)
	server.WriteTo(m.Bytes(), addr)
}

func handler(m *message) {
	m.Header.SetQR(1)
	m.Header.SetRA(1)

	for _, q := range m.Question {
		resMsg, err := resolve(q, m.Header.RD())
		if err != nil {
			log.Println(err)
			continue
		}
		m.Answer = append(m.Answer, resMsg.Answer...)
		m.Authority = append(m.Authority, resMsg.Authority...)
		m.Additional = append(m.Additional, resMsg.Additional...)
	}
}
