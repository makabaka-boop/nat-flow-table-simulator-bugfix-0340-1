package natsim

import (
	"net/netip"
	"time"
)

// hairpinFlow binds a loopback session to the published peer it dialed. It is
// carried by the client mapping, so expiring or deleting that mapping retires
// the flow at the same instant.
type hairpinFlow struct {
	// PeerPort is the published public UDP port the client dialed.
	PeerPort uint16
	// PeerInternal is the published local endpoint at session creation.
	PeerInternal netip.AddrPort
	// Revision is the publication revision this session belongs to.
	Revision uint64
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

	// A packet to the translated source of an existing loopback session is a
	// reply from the published peer. Published ports are never allocated to
	// mappings, so a dialed port and a session port cannot collide.
	if m := s.byPort[dst.Port()]; m != nil && m.hairpin != nil {
		return s.hairpinReplyLocked(now, m, pkt, src)
	}
	return s.hairpinDialLocked(now, pkt, src, dst)
}

// hairpinReplyLocked forwards a published peer's reply back to the loopback
// client that dialed it. The session is valid only while the publication
// revision it was created under is still current, and only the published
// endpoint itself may reply.
func (s *Service) hairpinReplyLocked(now time.Time, m *mapping, original Packet, src netip.AddrPort) Result {
	flow := m.hairpin
	rule, current := s.publications[flow.PeerPort]
	if !current || rule.Revision != flow.Revision {
		// The publication was revoked or replaced: the old publication
		// identity's session must not survive.
		s.deleteMappingLocked(m)
		return reject(Outbound, original, ReasonNoMapping)
	}
	if src != flow.PeerInternal {
		return reject(Outbound, original, ReasonRemoteMismatch)
	}
	m.touch(now)
	return Result{
		Direction: Outbound,
		Original:  original,
		Translated: Packet{
			Protocol:    UDP,
			Source:      netip.AddrPortFrom(s.publicIP, flow.PeerPort),
			Destination: netip.AddrPortFrom(netip.AddrFrom4(m.key.InternalAddr), m.key.InternalPort),
		},
		Key:        m.key,
		PublicPort: m.public.Port(),
		ExpiresAt:  m.expiresAt,
		Allowed:    true,
		Reason:     ReasonNone,
	}
}

// hairpinDialLocked starts or refreshes a loopback session from a local client
// to a published public endpoint. Permission is decided before any state
// change: a rejected packet neither creates nor refreshes a session.
func (s *Service) hairpinDialLocked(now time.Time, original Packet, src, dst netip.AddrPort) Result {
	rule, ok := s.publications[dst.Port()]
	if !ok {
		return reject(Outbound, original, ReasonNoMapping)
	}
	permitted := false
	for _, peer := range rule.Allowed {
		if peer == src {
			permitted = true
			break
		}
	}
	if !permitted {
		return reject(Outbound, original, ReasonRemoteMismatch)
	}
	key := MappingKey{
		InternalAddr: src.Addr().As4(),
		InternalPort: src.Port(),
		RemoteAddr:   dst.Addr().As4(),
		RemotePort:   dst.Port(),
	}
	m, exists := s.mappings[key]
	created := false
	if !exists {
		port, free := s.smallestFreePortLocked()
		if !free {
			return reject(Outbound, original, ReasonPortsExhausted)
		}
		m = &mapping{key: key, public: netip.AddrPortFrom(s.publicIP, port)}
		s.mappings[key] = m
		s.byPort[port] = m
		created = true
	}
	// (Re)bind the session to the current publication identity.
	m.hairpin = &hairpinFlow{PeerPort: rule.Port, PeerInternal: rule.Internal, Revision: rule.Revision}
	m.touch(now)
	return Result{
		Direction:  Outbound,
		Original:   original,
		Translated: Packet{Protocol: UDP, Source: m.public, Destination: rule.Internal},
		Key:        key,
		PublicPort: m.public.Port(),
		Created:    created,
		ExpiresAt:  m.expiresAt,
		Allowed:    true,
		Reason:     ReasonNone,
	}
}
