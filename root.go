package main

import (
	"bufio"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
)

type Zone struct {
	Name string
	RRs  map[uint16][]resourceRecord
}

type SourceOfAuth struct {
	Name    string
	Class   string
	MName   string
	RName   string
	Serial  int32
	Refresh int32
	Retry   int32
	Expire  int32
	Minimum int32
	Ttl     int32
}

type Root struct {
	Zones map[string]*Zone
	SOA   SourceOfAuth
}

type tokens = []string

var root = Root{
	Zones: make(map[string]*Zone),
}

var RRTypes = map[string]uint16{
	"A":    1,
	"NS":   2,
	"AAAA": 28,
}

var RRClasses = map[string]uint16{
	"IN": 1,
}

func NewSOA(t tokens) SourceOfAuth {
	soa := SourceOfAuth{
		Name:    t[0],
		Class:   t[2],
		MName:   t[4],
		RName:   t[5],
		Ttl:     parseInt32(t[1]),
		Serial:  parseInt32(t[6]),
		Refresh: parseInt32(t[7]),
		Retry:   parseInt32(t[8]),
		Expire:  parseInt32(t[9]),
		Minimum: parseInt32(t[10]),
	}
	return soa
}

func AppendNewRR(t tokens, z *Zone) {
	rr := resourceRecord{
		Name:  t[0],
		Class: RRClasses[t[2]],
		Type:  RRTypes[t[3]],
		Data:  t[4],
		Ttl:   parseInt32(t[1]),
	}
	z.RRs[rr.Type] = append(z.RRs[rr.Type], rr)
}

func ParseRoot(f *os.File) {
	reader := bufio.NewReader(f)
	// assuming the first line is the SOA
	soaLine, err := reader.ReadString('\n')
	if err != nil {
		panic(err)
	}
	soaLine = sanitize(soaLine)
	soa := NewSOA(strings.Split(soaLine, " "))
	root.SOA = soa

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			panic(err)
		}
		line = sanitize(line)
		if line == "" {
			continue
		}
		tokens := strings.Split(line, " ")
		rrType := tokens[3]
		_, supported := RRTypes[rrType]
		if !supported {
			continue
		}
		name := tokens[0]
		zone, exists := root.Zones[name]
		if !exists {
			root.Zones[name] = &Zone{
				Name: name,
				RRs:  make(map[uint16][]resourceRecord),
			}
			zone = root.Zones[name]
		}

		AppendNewRR(tokens, zone)
	}
}

func parseInt32(str string) int32 {
	i, err := strconv.ParseInt(str, 10, 32)
	if err != nil {
		return -1
	}
	return int32(i)
}

var spacesOrTabs = regexp.MustCompile(`[\s\t]+`)

const (
	cutset     string = " \n\t"
	commentSep string = ";"
)

func sanitize(line string) string {
	line = strings.TrimLeft(line, cutset)
	if len(line) == 0 || line[0] == commentSep[0] {
		return ""
	}
	line, _, _ = strings.Cut(line, commentSep)
	line = strings.TrimRight(line, cutset)
	line = spacesOrTabs.ReplaceAllString(line, " ")
	return line
}
