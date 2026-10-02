package natsim

import (
	"fmt"
	"net/netip"
)

type Publication struct {
	Port     uint16
	Internal netip.AddrPort
	Allowed  []netip.AddrPort
	Revision uint64
}

// Publish replaces a simulated local peer's public UDP endpoint.
func (s *Service) Publish(port uint16, internal netip.AddrPort, allowed []netip.AddrPort, expected uint64) (Publication, error) {
	target, ok := validUDPAddrPort(internal)
	if !ok || target.Addr() == s.publicIP || port < MinPublicPort || port > MaxPublicPort {
		return Publication{}, fmt.Errorf("invalid publication")
	}
	peers := make([]netip.AddrPort, len(allowed))
	for i, p := range allowed {
		v, ok := validUDPAddrPort(p)
		if !ok {
			return Publication{}, fmt.Errorf("invalid allowed peer")
		}
		peers[i] = v
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if expected != s.publicationRevision {
		return Publication{}, fmt.Errorf("publication revision conflict")
	}
	if s.publications == nil {
		s.publications = map[uint16]Publication{}
	}
	s.publicationRevision++
	rule := Publication{Port: port, Internal: target, Allowed: peers, Revision: s.publicationRevision}
	s.publications[port] = rule
	return rule, nil
}

func (s *Service) Unpublish(port uint16, expected uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if expected != s.publicationRevision {
		return fmt.Errorf("publication revision conflict")
	}
	if _, ok := s.publications[port]; !ok {
		return fmt.Errorf("publication not found")
	}
	delete(s.publications, port)
	s.publicationRevision++
	return nil
}

func (s *Service) PublicationRevision() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.publicationRevision
}

func (s *Service) Publications() []Publication {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Publication{}
	for p := MinPublicPort; p <= MaxPublicPort; p++ {
		if rule, ok := s.publications[p]; ok {
			rule.Allowed = append([]netip.AddrPort(nil), rule.Allowed...)
			out = append(out, rule)
		}
	}
	return out
}
