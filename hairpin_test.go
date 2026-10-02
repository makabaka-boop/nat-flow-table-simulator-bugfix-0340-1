package natsim

import (
	"net/netip"
	"testing"
	"time"
)

var hairpinEpoch = time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

func hpAp(addr string, port uint16) netip.AddrPort {
	return netip.AddrPortFrom(netip.MustParseAddr(addr), port)
}

func hpUdp(src, dst netip.AddrPort) Packet {
	return Packet{Protocol: UDP, Source: src, Destination: dst}
}

func hpNewNAT(t *testing.T) (*Service, *ControlledClock) {
	t.Helper()
	clock := NewControlledClock(hairpinEpoch)
	svc, err := New(netip.MustParseAddr("192.0.2.1"), clock)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return svc, clock
}

func hpPublic(svc *Service, port uint16) netip.AddrPort {
	return netip.AddrPortFrom(svc.PublicIP(), port)
}

func TestHairpinDialAndReplyIdentities(t *testing.T) {
	svc, clock := hpNewNAT(t)
	receiver := hpAp("10.0.0.20", 7000)
	client := hpAp("10.0.0.30", 8000)
	rule, err := svc.Publish(40010, receiver, []netip.AddrPort{client}, 0)
	if err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	if rule.Revision != 1 {
		t.Fatalf("first publication revision = %d, want 1", rule.Revision)
	}

	dial := svc.TranslateHairpin(hpUdp(client, hpAp("192.0.2.1", 40010)))
	if !dial.Allowed || !dial.Created {
		t.Fatalf("dial = %+v, want accepted new session", dial)
	}
	if dial.PublicPort == 40010 {
		t.Fatalf("client session took the published port %d", dial.PublicPort)
	}
	if dial.Translated.Source != hpPublic(svc, dial.PublicPort) || dial.Translated.Destination != receiver {
		t.Fatalf("dial translation = %s, want %s => %s",
			dial.Translated, hpPublic(svc, dial.PublicPort), receiver)
	}
	if dial.ExpiresAt != hairpinEpoch.Add(30*time.Second) {
		t.Fatalf("dial expiry = %v, want %v", dial.ExpiresAt, hairpinEpoch.Add(30*time.Second))
	}

	clock.Advance(5 * time.Second)
	reply := svc.TranslateHairpin(hpUdp(receiver, hpPublic(svc, dial.PublicPort)))
	if !reply.Allowed || reply.Created {
		t.Fatalf("reply = %+v, want accepted existing session", reply)
	}
	if reply.Translated.Source != hpAp("192.0.2.1", 40010) || reply.Translated.Destination != client {
		t.Fatalf("reply translation = %s, want %s => %s",
			reply.Translated, hpAp("192.0.2.1", 40010), client)
	}
	if reply.ExpiresAt != hairpinEpoch.Add(35*time.Second) {
		t.Fatalf("reply refreshed expiry = %v, want %v", reply.ExpiresAt, hairpinEpoch.Add(35*time.Second))
	}
	if got := svc.ActiveMappings(); got != 1 {
		t.Fatalf("active mappings = %d, want 1", got)
	}
}

func TestHairpinDialNotAllowlistedLeavesNoSession(t *testing.T) {
	svc, _ := hpNewNAT(t)
	receiver := hpAp("10.0.0.20", 7000)
	client := hpAp("10.0.0.30", 8000)
	if _, err := svc.Publish(40010, receiver, []netip.AddrPort{client}, 0); err != nil {
		t.Fatalf("Publish() error = %v", err)
	}

	stranger := svc.TranslateHairpin(hpUdp(hpAp("10.0.0.99", 9000), hpAp("192.0.2.1", 40010)))
	if stranger.Allowed || stranger.Reason != ReasonRemoteMismatch {
		t.Fatalf("stranger dial = %+v, want RemoteMismatch rejection", stranger)
	}
	if got := svc.ActiveMappings(); got != 0 {
		t.Fatalf("rejected dial left %d active mappings, want 0", got)
	}

	// The rejected attempt consumed no port: the allowlisted client gets the
	// smallest one.
	dial := svc.TranslateHairpin(hpUdp(client, hpAp("192.0.2.1", 40010)))
	if !dial.Allowed || dial.PublicPort != MinPublicPort {
		t.Fatalf("allowlisted dial = %+v, want port %d", dial, MinPublicPort)
	}
}

func TestPublishedPortNotDynamicallyAllocated(t *testing.T) {
	svc, _ := hpNewNAT(t)
	if _, err := svc.Publish(40000, hpAp("10.0.0.20", 7000), nil, 0); err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	out := svc.Translate(Outbound, hpUdp(hpAp("10.0.0.40", 5000), hpAp("203.0.113.5", 53)))
	if !out.Allowed || out.PublicPort != 40001 {
		t.Fatalf("dynamic mapping port = %d, want 40001 (40000 is published)", out.PublicPort)
	}
	// Ordinary inbound traffic to the published port finds no mapping.
	in := svc.Translate(Inbound, hpUdp(hpAp("203.0.113.5", 53), hpAp("192.0.2.1", 40000)))
	if in.Allowed || in.Reason != ReasonNoMapping {
		t.Fatalf("inbound to published port = %+v, want NoMapping", in)
	}
}

func TestPublishFailsWhilePortOwnedByMapping(t *testing.T) {
	svc, clock := hpNewNAT(t)
	out := svc.Translate(Outbound, hpUdp(hpAp("10.0.0.40", 5000), hpAp("203.0.113.5", 53)))
	if !out.Allowed || out.PublicPort != 40000 {
		t.Fatalf("outbound = %+v, want port 40000", out)
	}
	if _, err := svc.Publish(40000, hpAp("10.0.0.20", 7000), nil, 0); err == nil {
		t.Fatal("Publish on actively mapped port unexpectedly succeeded")
	}
	if got := svc.PublicationRevision(); got != 0 {
		t.Fatalf("failed publish changed revision to %d, want 0", got)
	}
	if got := len(svc.Publications()); got != 0 {
		t.Fatalf("failed publish left %d publications, want 0", got)
	}
	// The mapping still owns the port.
	in := svc.Translate(Inbound, hpUdp(hpAp("203.0.113.5", 53), hpAp("192.0.2.1", 40000)))
	if !in.Allowed {
		t.Fatalf("mapping lost its port after failed publish: %s", in)
	}
	// Once the mapping expires the port becomes publishable.
	clock.Advance(30 * time.Second)
	if _, err := svc.Publish(40000, hpAp("10.0.0.20", 7000), nil, 0); err != nil {
		t.Fatalf("Publish after mapping expiry error = %v", err)
	}
}

func TestPublishReplacementTerminatesOldSessions(t *testing.T) {
	svc, clock := hpNewNAT(t)
	oldReceiver := hpAp("10.0.0.20", 7000)
	newReceiver := hpAp("10.0.0.21", 7001)
	client := hpAp("10.0.0.30", 8000)
	if _, err := svc.Publish(40010, oldReceiver, []netip.AddrPort{client}, 0); err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	dial := svc.TranslateHairpin(hpUdp(client, hpAp("192.0.2.1", 40010)))
	if !dial.Allowed {
		t.Fatalf("dial rejected: %s", dial)
	}
	oldClientPublic := hpPublic(svc, dial.PublicPort)

	clock.Advance(time.Second)
	rule, err := svc.Publish(40010, newReceiver, []netip.AddrPort{client}, 1)
	if err != nil {
		t.Fatalf("replacement Publish() error = %v", err)
	}
	if rule.Revision != 2 {
		t.Fatalf("replacement revision = %d, want 2", rule.Revision)
	}
	if got := svc.ActiveMappings(); got != 0 {
		t.Fatalf("replacement left %d old sessions, want 0", got)
	}

	// The old receiver's reply must not enter the terminated session.
	late := svc.TranslateHairpin(hpUdp(oldReceiver, oldClientPublic))
	if late.Allowed || late.Reason != ReasonNoMapping {
		t.Fatalf("old receiver reply = %+v, want NoMapping", late)
	}

	// A new dial is adjudicated under the current rule and reaches the new receiver.
	redial := svc.TranslateHairpin(hpUdp(client, hpAp("192.0.2.1", 40010)))
	if !redial.Allowed || !redial.Created {
		t.Fatalf("redial = %+v, want a new session", redial)
	}
	if redial.Translated.Destination != newReceiver {
		t.Fatalf("redial destination = %s, want %s", redial.Translated.Destination, newReceiver)
	}
	// The old receiver cannot use the new session; the new receiver can.
	wrong := svc.TranslateHairpin(hpUdp(oldReceiver, hpPublic(svc, redial.PublicPort)))
	if wrong.Allowed || wrong.Reason != ReasonRemoteMismatch {
		t.Fatalf("old receiver on new session = %+v, want RemoteMismatch", wrong)
	}
	ok := svc.TranslateHairpin(hpUdp(newReceiver, hpPublic(svc, redial.PublicPort)))
	if !ok.Allowed || ok.Translated.Destination != client {
		t.Fatalf("new receiver reply = %+v, want delivery to %s", ok, client)
	}
}

func TestUnpublishTerminatesSessions(t *testing.T) {
	svc, clock := hpNewNAT(t)
	receiver := hpAp("10.0.0.20", 7000)
	client := hpAp("10.0.0.30", 8000)
	if _, err := svc.Publish(40010, receiver, []netip.AddrPort{client}, 0); err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	dial := svc.TranslateHairpin(hpUdp(client, hpAp("192.0.2.1", 40010)))
	if !dial.Allowed {
		t.Fatalf("dial rejected: %s", dial)
	}
	clientPublic := hpPublic(svc, dial.PublicPort)

	clock.Advance(time.Second)
	if err := svc.Unpublish(40010, 1); err != nil {
		t.Fatalf("Unpublish() error = %v", err)
	}
	if got := svc.PublicationRevision(); got != 2 {
		t.Fatalf("revision after unpublish = %d, want 2", got)
	}
	if got := svc.ActiveMappings(); got != 0 {
		t.Fatalf("unpublish left %d sessions, want 0", got)
	}

	// Neither new dials nor late replies find anything.
	if r := svc.TranslateHairpin(hpUdp(client, hpAp("192.0.2.1", 40010))); r.Allowed || r.Reason != ReasonNoMapping {
		t.Fatalf("dial after unpublish = %+v, want NoMapping", r)
	}
	if r := svc.TranslateHairpin(hpUdp(receiver, clientPublic)); r.Allowed || r.Reason != ReasonNoMapping {
		t.Fatalf("reply after unpublish = %+v, want NoMapping", r)
	}

	// Both the published port and the session port return to the pool.
	out := svc.Translate(Outbound, hpUdp(hpAp("10.0.0.40", 5000), hpAp("203.0.113.5", 53)))
	if !out.Allowed || out.PublicPort != 40000 {
		t.Fatalf("first allocation after unpublish = %+v, want port 40000", out)
	}
	if _, err := svc.Publish(40010, receiver, nil, 2); err != nil {
		t.Fatalf("re-publish after unpublish error = %v", err)
	}
}

func TestHairpinExpiryAndPortReuse(t *testing.T) {
	svc, clock := hpNewNAT(t)
	receiver := hpAp("10.0.0.20", 7000)
	client := hpAp("10.0.0.30", 8000)
	if _, err := svc.Publish(40010, receiver, []netip.AddrPort{client}, 0); err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	dial := svc.TranslateHairpin(hpUdp(client, hpAp("192.0.2.1", 40010)))
	if !dial.Allowed || dial.PublicPort != 40000 {
		t.Fatalf("dial = %+v, want port 40000", dial)
	}
	clientPublic := hpPublic(svc, 40000)

	// One nanosecond short of the deadline the session is still usable.
	clock.Advance(30*time.Second - time.Nanosecond)
	alive := svc.TranslateHairpin(hpUdp(receiver, clientPublic))
	if !alive.Allowed {
		t.Fatalf("reply before deadline rejected: %s", alive)
	}

	// Exactly at the refreshed deadline the session is gone.
	clock.Advance(30 * time.Second)
	if got := svc.ActiveMappings(); got != 0 {
		t.Fatalf("session survived its deadline; active=%d", got)
	}

	// Another device takes the recycled port for an ordinary mapping.
	other := svc.Translate(Outbound, hpUdp(hpAp("10.0.0.50", 6000), hpAp("203.0.113.9", 9000)))
	if !other.Allowed || other.PublicPort != 40000 {
		t.Fatalf("recycled port mapping = %+v, want port 40000", other)
	}

	// The late reply must not reach the new port owner.
	late := svc.TranslateHairpin(hpUdp(receiver, clientPublic))
	if late.Allowed {
		t.Fatalf("late reply after port reuse was delivered: %s", late)
	}
	if late.Reason != ReasonNoMapping {
		t.Fatalf("late reply reason = %q, want %q", late.Reason, ReasonNoMapping)
	}
	// The new owner's ordinary inbound traffic is unaffected.
	in := svc.Translate(Inbound, hpUdp(hpAp("203.0.113.9", 9000), hpAp("192.0.2.1", 40000)))
	if !in.Allowed || in.Translated.Destination != hpAp("10.0.0.50", 6000) {
		t.Fatalf("new owner inbound = %+v", in)
	}
}

func TestRejectedReplyDoesNotRefreshSession(t *testing.T) {
	svc, clock := hpNewNAT(t)
	receiver := hpAp("10.0.0.20", 7000)
	client := hpAp("10.0.0.30", 8000)
	if _, err := svc.Publish(40010, receiver, []netip.AddrPort{client}, 0); err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	dial := svc.TranslateHairpin(hpUdp(client, hpAp("192.0.2.1", 40010)))
	if !dial.Allowed {
		t.Fatalf("dial rejected: %s", dial)
	}
	clientPublic := hpPublic(svc, dial.PublicPort)

	clock.Advance(29 * time.Second)
	// A spoofed reply from another local device is rejected and must not refresh.
	spoof := svc.TranslateHairpin(hpUdp(hpAp("10.0.0.99", 7000), clientPublic))
	if spoof.Allowed || spoof.Reason != ReasonRemoteMismatch {
		t.Fatalf("spoofed reply = %+v, want RemoteMismatch", spoof)
	}
	clock.Advance(time.Second)
	if got := svc.ActiveMappings(); got != 0 {
		t.Fatalf("rejected reply refreshed the session; active=%d", got)
	}
}

func TestReplacementReadjudicatesAllowlist(t *testing.T) {
	svc, _ := hpNewNAT(t)
	receiver := hpAp("10.0.0.20", 7000)
	oldClient := hpAp("10.0.0.30", 8000)
	newClient := hpAp("10.0.0.31", 8001)
	if _, err := svc.Publish(40010, receiver, []netip.AddrPort{oldClient}, 0); err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	if r := svc.TranslateHairpin(hpUdp(oldClient, hpAp("192.0.2.1", 40010))); !r.Allowed {
		t.Fatalf("old client dial rejected: %s", r)
	}

	// Replace with an allowlist that drops the old client.
	if _, err := svc.Publish(40010, receiver, []netip.AddrPort{newClient}, 1); err != nil {
		t.Fatalf("replacement Publish() error = %v", err)
	}
	if r := svc.TranslateHairpin(hpUdp(oldClient, hpAp("192.0.2.1", 40010))); r.Allowed || r.Reason != ReasonRemoteMismatch {
		t.Fatalf("old client after replacement = %+v, want RemoteMismatch", r)
	}
	if got := svc.ActiveMappings(); got != 0 {
		t.Fatalf("rejected old client left %d sessions, want 0", got)
	}
	if r := svc.TranslateHairpin(hpUdp(newClient, hpAp("192.0.2.1", 40010))); !r.Allowed {
		t.Fatalf("new client dial rejected: %s", r)
	}
	if got := svc.ActiveMappings(); got != 1 {
		t.Fatalf("active mappings = %d, want 1", got)
	}
}

func TestTwoDevicesExchangeThroughPublications(t *testing.T) {
	svc, clock := hpNewNAT(t)
	devA := hpAp("10.0.0.30", 8000)
	devB := hpAp("10.0.0.20", 7000)
	if _, err := svc.Publish(40011, devA, []netip.AddrPort{devB}, 0); err != nil {
		t.Fatalf("Publish A error = %v", err)
	}
	if _, err := svc.Publish(40012, devB, []netip.AddrPort{devA}, 1); err != nil {
		t.Fatalf("Publish B error = %v", err)
	}

	aToB := svc.TranslateHairpin(hpUdp(devA, hpAp("192.0.2.1", 40012)))
	bToA := svc.TranslateHairpin(hpUdp(devB, hpAp("192.0.2.1", 40011)))
	if !aToB.Allowed || !bToA.Allowed {
		t.Fatalf("dials: A->B %s; B->A %s", aToB, bToA)
	}
	if aToB.PublicPort == bToA.PublicPort {
		t.Fatalf("sessions share public port %d", aToB.PublicPort)
	}

	clock.Advance(time.Second)
	replyB := svc.TranslateHairpin(hpUdp(devB, hpPublic(svc, aToB.PublicPort)))
	if !replyB.Allowed || replyB.Translated.Destination != devA || replyB.Translated.Source != hpAp("192.0.2.1", 40012) {
		t.Fatalf("B reply = %+v", replyB)
	}
	replyA := svc.TranslateHairpin(hpUdp(devA, hpPublic(svc, bToA.PublicPort)))
	if !replyA.Allowed || replyA.Translated.Destination != devB || replyA.Translated.Source != hpAp("192.0.2.1", 40011) {
		t.Fatalf("A reply = %+v", replyA)
	}
	if got := svc.ActiveMappings(); got != 2 {
		t.Fatalf("active mappings = %d, want 2", got)
	}
}

func TestPublicationRevisionConflicts(t *testing.T) {
	svc, _ := hpNewNAT(t)
	receiver := hpAp("10.0.0.20", 7000)
	if _, err := svc.Publish(40010, receiver, nil, 5); err == nil {
		t.Fatal("Publish with wrong expected revision succeeded")
	}
	if _, err := svc.Publish(40010, receiver, nil, 0); err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	if _, err := svc.Publish(40011, receiver, nil, 0); err == nil {
		t.Fatal("Publish with stale revision succeeded")
	}
	if err := svc.Unpublish(40010, 0); err == nil {
		t.Fatal("Unpublish with stale revision succeeded")
	}
	if err := svc.Unpublish(40011, 1); err == nil {
		t.Fatal("Unpublish of unknown port succeeded")
	}
	if got := svc.PublicationRevision(); got != 1 {
		t.Fatalf("revision = %d, want 1", got)
	}
	if got := len(svc.Publications()); got != 1 {
		t.Fatalf("publications = %d, want 1", got)
	}
}

func TestPublicationsListedInPortOrder(t *testing.T) {
	svc, _ := hpNewNAT(t)
	if _, err := svc.Publish(40020, hpAp("10.0.0.20", 7000), []netip.AddrPort{hpAp("10.0.0.30", 8000)}, 0); err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	if _, err := svc.Publish(40010, hpAp("10.0.0.21", 7001), nil, 1); err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	pubs := svc.Publications()
	if len(pubs) != 2 || pubs[0].Port != 40010 || pubs[1].Port != 40020 {
		t.Fatalf("publications = %+v", pubs)
	}
	if pubs[0].Revision != 2 || pubs[1].Revision != 1 {
		t.Fatalf("revisions = %d, %d, want 2, 1", pubs[0].Revision, pubs[1].Revision)
	}
	// Mutating the returned allowlist must not affect the stored rule.
	pubs[1].Allowed[0] = hpAp("10.9.9.9", 1)
	if got := svc.Publications()[1].Allowed[0]; got != hpAp("10.0.0.30", 8000) {
		t.Fatalf("returned publication aliases stored allowlist: %v", got)
	}
}

func TestHairpinPortExhaustion(t *testing.T) {
	svc, _ := hpNewNAT(t)
	if _, err := svc.Publish(40000, hpAp("10.0.0.20", 7000), []netip.AddrPort{hpAp("10.0.0.30", 8000)}, 0); err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	const count = int(MaxPublicPort-MinPublicPort) + 1
	for i := 1; i < count; i++ {
		pkt := hpUdp(hpAp("10.1.0.1", uint16(2000+i)), hpAp("198.51.100.1", uint16(3000+i)))
		if r := svc.Translate(Outbound, pkt); !r.Allowed {
			t.Fatalf("mapping %d rejected: %s", i, r)
		}
	}
	// Every remaining port is taken; a hairpin dial has nowhere to go.
	r := svc.TranslateHairpin(hpUdp(hpAp("10.0.0.30", 8000), hpAp("192.0.2.1", 40000)))
	if r.Allowed || r.Reason != ReasonPortsExhausted {
		t.Fatalf("hairpin dial with full pool = %+v, want PortsExhausted", r)
	}
	if got := svc.ActiveMappings(); got != count-1 {
		t.Fatalf("active mappings = %d, want %d", got, count-1)
	}
}
