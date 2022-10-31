package httpcheck

import (
	"fmt"
	"sync"
)

type LocalResolver struct {
	mu        sync.RWMutex
	curPort   int32
	addresses map[string]string
}

func NewLocalResolver() *LocalResolver {
	return &LocalResolver{
		addresses: make(map[string]string),
	}
}

func (l *LocalResolver) Add(fqdn, addr string) string {
	l.mu.Lock()
	defer l.mu.Unlock()

	fqdn = fmt.Sprintf("%s:%d", fqdn, l.lockedPort())
	l.addresses[fqdn] = addr
	return fqdn
}

func (l *LocalResolver) Del(fqdn string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	delete(l.addresses, fqdn)
}

func (l *LocalResolver) Lookup(fqdn string) (string, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	addr, ok := l.addresses[fqdn]
	return addr, ok
}

func (l *LocalResolver) lockedPort() int32 {
	l.curPort++
	if l.curPort <= 0 {
		l.curPort = 1
	}
	return l.curPort
}
