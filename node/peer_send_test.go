package node

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	meshcore "github.com/meshcore-go/meshcore-go"
)

func tenMsPerByte(n int) uint32 { return uint32(n * 10) }

func newPeerSendNode(t *testing.T, opts ...Option) (*Node, *mockTxRadio, meshcore.LocalIdentity) {
	t.Helper()
	radio := &mockTxRadio{}
	n := New(seedIdentity(0x41), radio, append([]Option{WithAirtimeEstimator(tenMsPerByte)}, opts...)...)
	t.Cleanup(n.Stop)
	return n, radio, seedIdentity(0x42)
}

func decryptFor(t *testing.T, peer meshcore.LocalIdentity, sender meshcore.Identity, decrypt func([]byte) []byte) []byte {
	t.Helper()
	secret, err := peer.SharedSecret(sender)
	if err != nil {
		t.Fatal(err)
	}
	plain := decrypt(secret)
	if plain == nil {
		t.Fatal("peer could not decrypt the payload")
	}
	return plain
}

func TestNode_SendToPeer_Flood(t *testing.T) {
	sco := meshcore.NewRegionFromHashtag("sco")
	n, radio, _ := newPeerSendNode(t, WithFloodScope(sco))

	pkt := &meshcore.Packet{Header: meshcore.MakeHeader(meshcore.RouteTypeDirect, meshcore.PayloadTypeReq, 0), Payload: []byte{1, 2, 3, 4}}
	sent, err := n.SendToPeer(pkt, nil, 2)
	if err != nil {
		t.Fatal(err)
	}
	got := lastEnqueued(t, radio)
	wantScoped(t, got, sco)
	wire, _ := got.ToBytes()
	if want := CalcFloodTimeout(tenMsPerByte(len(wire))); !sent.Flood || sent.Timeout != want {
		t.Errorf("sent %+v, want a flood with timeout %v", sent, want)
	}
	if got.PathHashSize() != 2 || got.PathHashCount() != 0 {
		t.Errorf("path length 0x%02x, want 2-byte hashes and no hops", got.PathLength)
	}
}

func TestNode_SendToPeer_Direct(t *testing.T) {
	n, radio, _ := newPeerSendNode(t, WithFloodScope(meshcore.NewRegionFromHashtag("sco")))

	path := []byte{0xa1, 0xa2, 0xb1, 0xb2, 0xc1, 0xc2}
	pkt := &meshcore.Packet{Header: meshcore.MakeHeader(meshcore.RouteTypeFlood, meshcore.PayloadTypeReq, 0), Payload: []byte{1, 2, 3, 4}}
	sent, err := n.SendToPeer(pkt, path, 2)
	if err != nil {
		t.Fatal(err)
	}
	got := lastEnqueued(t, radio)
	if got.RouteType() != meshcore.RouteTypeDirect || got.PathLength != 0x43 || !bytes.Equal(got.Path, path) {
		t.Fatalf("route %d path length 0x%02x path %x, want direct over three 2-byte hops", got.RouteType(), got.PathLength, got.Path)
	}
	wire, _ := got.ToBytes()
	if want := CalcDirectTimeout(tenMsPerByte(len(wire)), 3); sent.Flood || sent.Timeout != want {
		t.Errorf("sent %+v, want direct with timeout %v", sent, want)
	}
}

func TestNode_SendToPeer_RefusesBadPaths(t *testing.T) {
	n, radio, _ := newPeerSendNode(t)
	pkt := func() *meshcore.Packet {
		return &meshcore.Packet{Header: meshcore.MakeHeader(meshcore.RouteTypeFlood, meshcore.PayloadTypeReq, 0), Payload: []byte{1}}
	}
	for _, tt := range []struct {
		name     string
		path     []byte
		hashSize uint8
	}{
		{"hash size 0", nil, 0},
		{"hash size 4", nil, 4},
		{"path not whole hashes", []byte{1, 2, 3}, 2},
		{"path over 64 bytes", make([]byte, 66), 3},
		{"more than 63 hops", make([]byte, 64), 1},
	} {
		if _, err := n.SendToPeer(pkt(), tt.path, tt.hashSize); err == nil {
			t.Errorf("%s: sent without error", tt.name)
		}
	}
	if len(radio.enqueued()) != 0 {
		t.Errorf("%d packets enqueued, want none", len(radio.enqueued()))
	}
}

func TestNode_SendTextOnce(t *testing.T) {
	ts := time.Unix(1790897222, 0)
	tests := []struct {
		name     string
		txtType  byte
		attempt  int
		wantFlag byte
		wantTail []byte
		acked    bool
	}{
		{name: "plain first attempt", txtType: 0, attempt: 0, wantFlag: 0x00, acked: true},
		{name: "plain attempt 2", txtType: 0, attempt: 2, wantFlag: 0x02, acked: true},
		{name: "plain attempt 5 rides after the NUL", txtType: 0, attempt: 5, wantFlag: 0x01, wantTail: []byte{0, 5}, acked: true},
		{name: "cli data is never acked", txtType: 1, attempt: 6, wantFlag: 0x06},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n, radio, bob := newPeerSendNode(t)
			text := []byte("get radio")

			sent, err := n.SendTextOnce(bob.Identity, tt.txtType, tt.attempt, ts, text, nil, 1, nil)
			if err != nil {
				t.Fatal(err)
			}
			got := lastEnqueued(t, radio)
			msg, err := meshcore.TextMessageFromBytes(got.Payload)
			if err != nil {
				t.Fatal(err)
			}
			plain := decryptFor(t, bob, n.Identity().Identity, msg.Decrypt)
			if plain[4] != tt.wantFlag {
				t.Errorf("flags byte 0x%02x, want 0x%02x", plain[4], tt.wantFlag)
			}
			body := plain[5 : 5+len(text)+len(tt.wantTail)]
			if !bytes.Equal(body, append(append([]byte{}, text...), tt.wantTail...)) {
				t.Errorf("body %x, want text then tail %x", body, tt.wantTail)
			}
			if rest := plain[5+len(text)+len(tt.wantTail):]; bytes.Count(rest, []byte{0}) != len(rest) {
				t.Errorf("bytes after the body %x, want only cipher padding", rest)
			}
			wantAck := uint32(0)
			if tt.acked {
				wantAck = meshcore.CalcAckHash(plain[:5+len(text)], n.Identity().PublicKeyBytes())
			}
			if sent.AckCRC != wantAck {
				t.Errorf("AckCRC %08x, want %08x as the recipient computes it", sent.AckCRC, wantAck)
			}
		})
	}
}

func TestNode_SendTextOnce_ReportsTheAck(t *testing.T) {
	n, radio, bob := newPeerSendNode(t)
	results := make(chan DMSendResult, 1)
	sent, err := n.SendTextOnce(bob.Identity, 0, 0, time.Unix(1790897222, 0), []byte("hi"), []byte{0x7a}, 1, func(r DMSendResult) { results <- r })
	if err != nil {
		t.Fatal(err)
	}
	n.NotifyACK(sent.AckCRC)
	select {
	case r := <-results:
		if !r.Confirmed {
			t.Errorf("result %+v, want confirmed", r)
		}
	case <-time.After(time.Second):
		t.Fatal("no result after the ACK")
	}
	if calls := radio.enqueued(); len(calls) != 1 {
		t.Errorf("%d packets enqueued, want exactly one send and no retries", len(calls))
	}
}

func TestNode_SendTextOnce_Refuses(t *testing.T) {
	n, radio, bob := newPeerSendNode(t)
	ts := time.Unix(1, 0)
	if _, err := n.SendTextOnce(bob.Identity, 2, 0, ts, []byte("x"), nil, 1, nil); err == nil {
		t.Error("signed text sent without error")
	}
	if _, err := n.SendTextOnce(bob.Identity, 0, 0, ts, make([]byte, meshcore.MaxTextLen+1), nil, 1, nil); err == nil {
		t.Error("text over MaxTextLen sent without error")
	}
	if _, err := n.SendTextOnce(bob.Identity, 0, 4, ts, make([]byte, meshcore.MaxTextLen-1), nil, 1, nil); err == nil {
		t.Error("attempt 4 sent with no room for its tail")
	}
	if _, err := n.SendTextOnce(bob.Identity, 0, 4, ts, make([]byte, meshcore.MaxTextLen-2), nil, 1, nil); err != nil {
		t.Errorf("attempt 4 with room for its tail refused: %v", err)
	}
	if len(radio.enqueued()) != 1 {
		t.Errorf("%d packets enqueued, want only the one that fitted", len(radio.enqueued()))
	}
}

func TestNode_SendRequest(t *testing.T) {
	n, radio, bob := newPeerSendNode(t)
	data := []byte{0x03, 0xfe, 0, 0, 0}
	sent, err := n.SendRequest(bob.Identity, 0x0a0b0c0d, data, nil, 1)
	if err != nil || !sent.Flood {
		t.Fatalf("sent %+v err %v, want a flood", sent, err)
	}
	got := lastEnqueued(t, radio)
	if got.PayloadType() != meshcore.PayloadTypeReq {
		t.Fatalf("payload type %d, want a request", got.PayloadType())
	}
	req, err := meshcore.RequestFromBytes(got.Payload)
	if err != nil {
		t.Fatal(err)
	}
	plain := decryptFor(t, bob, n.Identity().Identity, req.Decrypt)
	if binary.LittleEndian.Uint32(plain) != 0x0a0b0c0d || !bytes.Equal(plain[4:4+len(data)], data) {
		t.Errorf("plaintext %x, want the tag then the data", plain)
	}
	if _, err := n.SendRequest(bob.Identity, 1, make([]byte, meshcore.MaxPacketPayload-15), nil, 1); err == nil {
		t.Error("oversized request sent without error")
	}
}

func TestNode_SendAnonRequest(t *testing.T) {
	n, radio, bob := newPeerSendNode(t)
	if _, err := n.SendAnonRequest(bob.Identity, 0x11223344, []byte("hunter2"), []byte{}, 1); err != nil {
		t.Fatal(err)
	}
	got := lastEnqueued(t, radio)
	if got.PayloadType() != meshcore.PayloadTypeAnonReq || got.RouteType() != meshcore.RouteTypeDirect || got.PathLength != 0 {
		t.Fatalf("type %d route %d path length %d, want a zero-hop anon request", got.PayloadType(), got.RouteType(), got.PathLength)
	}
	req, err := meshcore.AnonReqFromBytes(got.Payload)
	if err != nil {
		t.Fatal(err)
	}
	plain := decryptFor(t, bob, meshcore.NewIdentity(req.EphemeralPubKey), req.Decrypt)
	if binary.LittleEndian.Uint32(plain) != 0x11223344 || !bytes.HasPrefix(plain[4:], []byte("hunter2")) {
		t.Errorf("plaintext %x, want the tag then the password", plain)
	}
}

func TestNode_SendGroupData(t *testing.T) {
	sco := meshcore.NewRegionFromHashtag("sco")
	ch := testChannel("rns-tunnel")
	n, radio, _ := newPeerSendNode(t, WithFloodScope(sco))

	if err := n.SendGroupData(ch, 0x0102, []byte("frame"), nil, 1); err != nil {
		t.Fatal(err)
	}
	got := lastEnqueued(t, radio)
	wantScoped(t, got, sco)
	gd, err := meshcore.GroupDataFromBytes(got.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if plain := gd.Decrypt(ch.PSK[:]); !bytes.HasPrefix(plain, []byte{0x02, 0x01, 5, 'f', 'r', 'a', 'm', 'e'}) {
		t.Errorf("plaintext %x, want data type, length then data", plain)
	}
	if err := n.SendGroupData(ch, 1, make([]byte, meshcore.MaxGroupDataLen+1), nil, 1); err == nil {
		t.Error("oversized group data sent without error")
	}
}
