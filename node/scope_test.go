package node

import (
	"testing"
	"time"

	meshcore "github.com/meshcore-go/meshcore-go"
)

func lastEnqueued(t *testing.T, radio *mockTxRadio) *meshcore.Packet {
	t.Helper()
	calls := radio.enqueued()
	if len(calls) == 0 {
		t.Fatal("nothing was enqueued")
	}
	pkt, err := meshcore.PacketFromBytes(calls[len(calls)-1].data)
	if err != nil {
		t.Fatal(err)
	}
	return pkt
}

func wantScoped(t *testing.T, pkt *meshcore.Packet, r *meshcore.Region) {
	t.Helper()
	if r == nil {
		if pkt.RouteType() != meshcore.RouteTypeFlood {
			t.Fatalf("route type %d, want a plain flood", pkt.RouteType())
		}
		return
	}
	if pkt.RouteType() != meshcore.RouteTypeTransportFlood || !r.MatchesPacket(pkt) || pkt.TransportCode2 != 0 {
		t.Fatalf("route type %d codes %04x %04x, want a transport flood in %s", pkt.RouteType(), pkt.TransportCode1, pkt.TransportCode2, r.Name)
	}
}

func floodTestPacket() *meshcore.Packet {
	return &meshcore.Packet{
		Header:     meshcore.MakeHeader(meshcore.RouteTypeDirect, meshcore.PayloadTypeReq, 0),
		PathLength: 0x82,
		Path:       []byte{1, 2, 3, 4, 5, 6},
		Payload:    []byte{0xde, 0xad, 0xbe, 0xef},
	}
}

func TestNode_SendFlood_Scope(t *testing.T) {
	sco := meshcore.NewRegionFromHashtag("sco")
	fif := meshcore.NewRegionFromHashtag("fif")

	tests := []struct {
		name  string
		node  []Option
		set   *meshcore.Region
		opts  []SendOption
		scope *meshcore.Region
	}{
		{name: "no scope floods unscoped"},
		{name: "node scope", node: []Option{WithFloodScope(sco)}, scope: sco},
		{name: "scope set at runtime", set: fif, scope: fif},
		{name: "send scope beats node scope", node: []Option{WithFloodScope(sco)}, opts: []SendOption{InScope(fif)}, scope: fif},
		{name: "unscoped beats node scope", node: []Option{WithFloodScope(sco)}, opts: []SendOption{Unscoped()}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			radio := &mockTxRadio{}
			n := New(seedIdentity(0x31), radio, tt.node...)
			defer n.Stop()
			if tt.set != nil {
				n.SetFloodScope(tt.set)
			}

			if err := n.SendFlood(floodTestPacket(), tt.opts...); err != nil {
				t.Fatal(err)
			}
			pkt := lastEnqueued(t, radio)
			wantScoped(t, pkt, tt.scope)
			if pkt.PathLength != 0x80 || len(pkt.Path) != 0 {
				t.Errorf("path length 0x%02x path %x, want the 3-byte hash size kept and no hops", pkt.PathLength, pkt.Path)
			}
			if pkt.PayloadType() != meshcore.PayloadTypeReq {
				t.Errorf("payload type %d changed", pkt.PayloadType())
			}
		})
	}
}

func TestNode_SendGroupText_Scope(t *testing.T) {
	sco := meshcore.NewRegionFromHashtag("sco")
	ch := testChannel("scope-test")
	radio := &mockTxRadio{}
	n := New(seedIdentity(0x32), radio, WithChannels(ch), WithFloodScope(sco))
	defer n.Stop()

	if err := n.SendGroupText(ch, testGroupPayload("in scope"), 2, time.Second, 0, nil); err != nil {
		t.Fatal(err)
	}
	pkt := lastEnqueued(t, radio)
	wantScoped(t, pkt, sco)
	if pkt.PathHashSize() != 2 {
		t.Errorf("path hash size %d, want 2", pkt.PathHashSize())
	}

	if err := n.SendGroupText(ch, testGroupPayload("unscoped"), 1, time.Second, 0, nil, Unscoped()); err != nil {
		t.Fatal(err)
	}
	wantScoped(t, lastEnqueued(t, radio), nil)
}

func TestNode_SendTextMessage_ScopesFloodsOnly(t *testing.T) {
	sco := meshcore.NewRegionFromHashtag("sco")
	peer := seedIdentity(0x34).Identity
	radio := &mockTxRadio{}
	n := New(seedIdentity(0x33), radio, WithFloodScope(sco))
	defer n.Stop()

	if err := n.SendTextMessage(peer, []byte("flood"), 0, time.Unix(1790000000, 0), nil, 1, time.Minute, nil); err != nil {
		t.Fatal(err)
	}
	wantScoped(t, lastEnqueued(t, radio), sco)

	if err := n.SendTextMessage(peer, []byte("direct"), 0, time.Unix(1790000001, 0), []byte{0x7a}, 1, time.Minute, nil); err != nil {
		t.Fatal(err)
	}
	if pkt := lastEnqueued(t, radio); pkt.RouteType() != meshcore.RouteTypeDirect {
		t.Errorf("route type %d, want a direct send left unscoped", pkt.RouteType())
	}
}

func TestNode_SelfAdvert_UsesFloodScope(t *testing.T) {
	sco := meshcore.NewRegionFromHashtag("sco")
	radio := &mockTxRadio{}
	n := New(seedIdentity(0x35), radio, WithFloodScope(sco), WithAdvertData(meshcore.AdvertAppData{Type: "CHAT", Name: "Cadham"}))
	defer n.Stop()

	deadline := time.Now().Add(time.Second)
	for len(radio.enqueued()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	pkt := lastEnqueued(t, radio)
	if pkt.PayloadType() != meshcore.PayloadTypeAdvert {
		t.Fatalf("payload type %d, want an advert", pkt.PayloadType())
	}
	wantScoped(t, pkt, sco)
}
