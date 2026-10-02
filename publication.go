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
//
// Fixed publications and dynamic mappings share one port pool: Publish fails
// without changing the revision or port ownership while the port is owned by
// an active mapping. A successful replacement immediately terminates the
// previous publication identity's loopback sessions.
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
	now := s.clock.Now()
	s.sweepExpiredLocked(now)
	if _, occupied := s.byPort[port]; occupied {
		return Publication{}, fmt.Errorf("public port %d is owned by an active mapping", port)
	}
	// Replacing the publication retires the old identity's loopback sessions.
	s.terminatePublicationSessionsLocked(port)
	s.publicationRevision++
	if s.publications == nil {
		s.publications = map[uint16]Publication{}
	}
	rule := Publication{Port: port, Internal: target, Allowed: peers, Revision: s.publicationRevision}
	s.publications[port] = rule
	return rule, nil
}

// Unpublish removes a publication and immediately terminates its loopback
// sessions, so the revoked identity's replies find no session to enter.
func (s *Service) Unpublish(port uint16, expected uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if expected != s.publicationRevision {
		return fmt.Errorf("publication revision conflict")
	}
	if _, ok := s.publications[port]; !ok {
		return fmt.Errorf("publication not found")
	}
	s.terminatePublicationSessionsLocked(port)
	delete(s.publications, port)
	s.publicationRevision++
	return nil
}

// terminatePublicationSessionsLocked ends every loopback session created under
// the publication on pubPort. Deleting a client mapping deletes its hairpin
// flow with it, retiring the old publication identity immediately.
func (s *Service) terminatePublicationSessionsLocked(pubPort uint16) {
	for _, m := range s.byPort {
		if m.hairpin != nil && m.hairpin.PeerPort == pubPort {
			s.deleteMappingLocked(m)
		}
	}
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
