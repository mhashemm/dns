package main

import (
	"sync"
	"time"
)

type cachedRR struct {
	rr        resourceRecord
	createdAt time.Time
}

type cache struct {
	cache map[string][]cachedRR
	mutex *sync.Mutex
}

func (c *cache) Get(domain string) (*message, bool) {
	c.mutex.Lock()
	crrs, exists := c.cache[domain]
	c.mutex.Unlock()

	if !exists {
		return nil, false
	}

	minTtlCrr := crrs[0]
	for _, crr := range crrs {
		if crr.rr.Ttl < minTtlCrr.rr.Ttl {
			minTtlCrr = crr
		}
	}

	t := time.Since(minTtlCrr.createdAt).Seconds()
	if t > float64(minTtlCrr.rr.Ttl) {
		c.remove(domain)
		return nil, false
	}

	m := &message{
		Answer: make([]resourceRecord, 0, len(crrs)),
	}

	for _, crr := range crrs {
		rr := crr.rr
		rr.Ttl -= int32(t)
		switch crr.rr.Type {
		case 1, 28:
			m.Answer = append(m.Answer, rr)
		}
	}

	return m, true
}

func (c *cache) Add(domain string, rrs []resourceRecord) {
	crr := make([]cachedRR, 0, len(rrs))
	for _, rr := range rrs {
		if rr.Ttl <= 0 {
			continue
		}
		crr = append(crr, cachedRR{
			rr:        rr,
			createdAt: time.Now(),
		})
	}

	c.mutex.Lock()
	c.cache[domain] = crr
	c.mutex.Unlock()
}

func (c *cache) remove(domain string) {
	c.mutex.Lock()
	delete(c.cache, domain)
	c.mutex.Unlock()
}
