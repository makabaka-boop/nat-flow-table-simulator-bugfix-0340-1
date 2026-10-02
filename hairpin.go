package natsim

import "net/netip"

type hairpinFlow struct {
	Peer   Publication
	Source MappingKey
}

// TranslateHairpin handles a local peer talking to a published peer's public address.
// Ordinary remote traffic continues through Translate.
func (s *Service) TranslateHairpin(pkt Packet) Result {
	if pkt.Protocol != UDP {
		return reject(Outbound, pkt, ReasonNotUDP)
	}
	src, srcOK := validUDPAddrPort(pkt.Source)
	dst, dstOK := validUDPAddrPort(pkt.Destination)
	if !srcOK || src.Addr() == s.publicIP {
		return reject(Outbound, pkt, ReasonInvalidSource)
	}
	if !dstOK || dst.Addr() != s.publicIP {
		return reject(Outbound, pkt, ReasonInvalidDestination)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock.Now()
	s.sweepExpiredLocked(now)
	if s.hairpins == nil {
		s.hairpins = map[uint16]hairpinFlow{}
	}
	// A packet to an existing conversation's translated source is a reply.
	if flow, ok := s.hairpins[dst.Port()]; ok {
		m := s.byPort[dst.Port()]
		if m == nil {
			return reject(Outbound, pkt, ReasonNoMapping)
		}
		if src != flow.Peer.Internal {
			return reject(Outbound, pkt, ReasonRemoteMismatch)
		}
		m.touch(now)
		return Result{Direction: Outbound, Original: pkt, Translated: Packet{Protocol: UDP, Source: netip.AddrPortFrom(s.publicIP, flow.Peer.Port), Destination: netip.AddrPortFrom(netip.AddrFrom4(m.key.InternalAddr), m.key.InternalPort)}, Key: m.key, PublicPort: m.public.Port(), ExpiresAt: m.expiresAt, Allowed: true}
	}
	rule, ok := s.publications[dst.Port()]
	if !ok {
		return reject(Outbound, pkt, ReasonNoMapping)
	}
	key := MappingKey{InternalAddr: src.Addr().As4(), InternalPort: src.Port(), RemoteAddr: dst.Addr().As4(), RemotePort: dst.Port()}
	m, exists := s.mappings[key]
	created := false
	if !exists {
		port, free := s.smallestFreePortLocked()
		if !free {
			return reject(Outbound, pkt, ReasonPortsExhausted)
		}
		m = &mapping{key: key, public: netip.AddrPortFrom(s.publicIP, port)}
		s.mappings[key] = m
		s.byPort[port] = m
		created = true
	}
	m.touch(now)
	permitted := false
	for _, peer := range rule.Allowed {
		if peer == src {
			permitted = true
		}
	}
	if !permitted {
		return reject(Outbound, pkt, ReasonRemoteMismatch)
	}
	s.hairpins[m.public.Port()] = hairpinFlow{Peer: rule, Source: key}
	return Result{Direction: Outbound, Original: pkt, Translated: Packet{Protocol: UDP, Source: m.public, Destination: rule.Internal}, Key: key, PublicPort: m.public.Port(), Created: created, ExpiresAt: m.expiresAt, Allowed: true}
}
