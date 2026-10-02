package meshcore

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestDeriveRegionKey_Deterministic(t *testing.T) {
	k1 := DeriveRegionKey("#ch-fr")
	k2 := DeriveRegionKey("#ch-fr")
	if k1 != k2 {
		t.Error("same name should produce same key")
	}
}

func TestDeriveRegionKey_DifferentNames(t *testing.T) {
	k1 := DeriveRegionKey("#ch-fr")
	k2 := DeriveRegionKey("#us-west")
	if k1 == k2 {
		t.Error("different names should produce different keys")
	}
}

func TestRegionKey_IsZero(t *testing.T) {
	var zero RegionKey
	if !zero.IsZero() {
		t.Error("zero key should be zero")
	}
	k := DeriveRegionKey("#test")
	if k.IsZero() {
		t.Error("derived key should not be zero")
	}
}

func TestRegionKey_CalcTransportCode_Deterministic(t *testing.T) {
	key := DeriveRegionKey("#ch-fr")
	c1 := key.CalcTransportCode(PayloadTypeTxtMsg, []byte{0x01, 0x02})
	c2 := key.CalcTransportCode(PayloadTypeTxtMsg, []byte{0x01, 0x02})
	if c1 != c2 {
		t.Errorf("same inputs should produce same code: got %04X and %04X", c1, c2)
	}
}

func TestRegionKey_CalcTransportCode_DifferentPayloads(t *testing.T) {
	key := DeriveRegionKey("#ch-fr")
	c1 := key.CalcTransportCode(PayloadTypeTxtMsg, []byte{0x01, 0x02})
	c2 := key.CalcTransportCode(PayloadTypeTxtMsg, []byte{0x03, 0x04})
	if c1 == c2 {
		t.Error("different payloads should produce different codes")
	}
}

func TestRegionKey_CalcTransportCode_DifferentPayloadTypes(t *testing.T) {
	key := DeriveRegionKey("#ch-fr")
	payload := []byte{0x01, 0x02, 0x03}
	c1 := key.CalcTransportCode(PayloadTypeTxtMsg, payload)
	c2 := key.CalcTransportCode(PayloadTypeAdvert, payload)
	if c1 == c2 {
		t.Error("different payload types should produce different codes")
	}
}

func TestRegionKey_CalcTransportCode_DifferentKeys(t *testing.T) {
	k1 := DeriveRegionKey("#ch-fr")
	k2 := DeriveRegionKey("#us-west")
	payload := []byte{0x01, 0x02, 0x03}
	c1 := k1.CalcTransportCode(PayloadTypeTxtMsg, payload)
	c2 := k2.CalcTransportCode(PayloadTypeTxtMsg, payload)
	if c1 == c2 {
		t.Error("different keys should produce different codes")
	}
}

func TestRegionKey_CalcTransportCode_NotReserved(t *testing.T) {
	key := DeriveRegionKey("#test-reserved")
	for i := range 1000 {
		payload := []byte{byte(i >> 8), byte(i)}
		code := key.CalcTransportCode(PayloadTypeTxtMsg, payload)
		if code == 0x0000 {
			t.Fatalf("code 0x0000 should be reserved (i=%d)", i)
		}
		if code == 0xFFFF {
			t.Fatalf("code 0xFFFF should be reserved (i=%d)", i)
		}
	}
}

func TestNewRegionFromHashtag(t *testing.T) {
	tests := []struct {
		input    string
		wantName string
	}{
		{"#ch-fr", "#ch-fr"},
		{"ch-fr", "#ch-fr"},
		{"$private", "$private"},
	}
	for _, tt := range tests {
		r := NewRegionFromHashtag(tt.input)
		if r.Name != tt.wantName {
			t.Errorf("NewRegionFromHashtag(%q).Name = %q, want %q", tt.input, r.Name, tt.wantName)
		}
		if r.Key.IsZero() {
			t.Errorf("NewRegionFromHashtag(%q).Key should not be zero", tt.input)
		}
	}
}

func TestRegion_MatchesPacket(t *testing.T) {
	r := NewRegionFromHashtag("#ch-fr")
	payload := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	payloadType := PayloadTypeTxtMsg

	code := r.Key.CalcTransportCode(payloadType, payload)

	pkt := &Packet{
		Header:         MakeHeader(RouteTypeTransportFlood, payloadType, 0),
		PathLength:     0,
		Payload:        payload,
		TransportCode1: code,
	}

	if !r.MatchesPacket(pkt) {
		t.Error("region should match packet with correct transport code")
	}

	pkt.TransportCode1 = code + 1
	if r.MatchesPacket(pkt) {
		t.Error("region should not match packet with wrong transport code")
	}
}

func TestRegion_MatchesPacket_NonTransportReturnsFalse(t *testing.T) {
	r := NewRegionFromHashtag("#ch-fr")
	pkt := &Packet{
		Header:     MakeHeader(RouteTypeFlood, PayloadTypeTxtMsg, 0),
		PathLength: 0,
		Payload:    []byte{0x01},
	}
	if r.MatchesPacket(pkt) {
		t.Error("non-transport packet should not match any region")
	}
}

func TestRegion_DenyFlags(t *testing.T) {
	r := &Region{Flags: 0}
	if r.DenyFlood() {
		t.Error("no flags set should not deny flood")
	}
	if r.DenyDirect() {
		t.Error("no flags set should not deny direct")
	}

	r.Flags = RegionDenyFlood
	if !r.DenyFlood() {
		t.Error("DENY_FLOOD set should deny flood")
	}
	if r.DenyDirect() {
		t.Error("only DENY_FLOOD set should not deny direct")
	}

	r.Flags = RegionDenyFlood | RegionDenyDirect
	if !r.DenyFlood() || !r.DenyDirect() {
		t.Error("both flags set should deny both")
	}
}

func TestIsValidRegionNameChar(t *testing.T) {
	valid := []byte{'-', '$', '#', '0', '9', 'A', 'Z', 'a', 'z'}
	for _, c := range valid {
		if !IsValidRegionNameChar(c) {
			t.Errorf("expected %q to be valid", c)
		}
	}

	invalid := []byte{' ', '!', '@', '.', ',', '/', '(', ')'}
	for _, c := range invalid {
		if IsValidRegionNameChar(c) {
			t.Errorf("expected %q to be invalid", c)
		}
	}
}

func TestRegionKey_CalcTransportCode_Vectors(t *testing.T) {
	key := DeriveRegionKey("#nz")
	if got := hex.EncodeToString(key[:]); got != "eb87ee8817ba71315ac7be9c733b523a" {
		t.Fatalf("DeriveRegionKey(#nz) = %s", got)
	}
	cases := []struct {
		payload string
		want    uint16
	}{
		{"010203", 0x38ab},
		{"00c5ec", 0x0001},
		{"01b654", 0xfffe},
	}
	for _, c := range cases {
		p, _ := hex.DecodeString(c.payload)
		if got := key.CalcTransportCode(PayloadTypeTxtMsg, p); got != c.want {
			t.Errorf("CalcTransportCode(%s) = 0x%04x, want 0x%04x", c.payload, got, c.want)
		}
	}
}

func TestNewRegionFromKey(t *testing.T) {
	var key RegionKey
	copy(key[:], bytes.Repeat([]byte{0xA5}, RegionKeySize))
	r := NewRegionFromKey("$private", key)
	if r.Name != "$private" || r.Key != key || r.ID != 0 || r.Parent != 0 || r.Flags != 0 {
		t.Fatalf("NewRegionFromKey() = %+v", r)
	}
	if r.Key == DeriveRegionKey("$private") {
		t.Fatal("NewRegionFromKey re-derived the key from the name")
	}
}

func TestRegion_ScopeFlood_MatchesFirmwareOnAir(t *testing.T) {
	tests := []struct {
		region string
		wire   string
	}{
		{"sco", "104ea7000080d41ee22644b0ea3aee70958cc5f4e87a1cfdbb1f404396dc0a7be3e7030df7418affbf6aa11bcf6cde27a47cc7211ec96ca1bde9803974ef81749b3db281439c4a9b83f1c834348bbb6b403c0997a546b95fcd4a878b2c1ed40236c5a7618150aa342d0092507a5503b6f8ceff4e554d432d4d43"},
		{"fif", "1420f0000080cbf5616764dfb491465108a62c8c659083523012337f3179e3287689a5eeb629c4f9b002b87560c75779eecc450d8c4bb9c7fed1855e9dac2d71002c18030b1aa445f3"},
	}
	for _, tt := range tests {
		t.Run(tt.region, func(t *testing.T) {
			wire, _ := hex.DecodeString(tt.wire)
			heard, err := PacketFromBytes(wire)
			if err != nil {
				t.Fatal(err)
			}
			pkt := heard.Clone()
			pkt.Header = MakeHeader(RouteTypeFlood, heard.PayloadType(), heard.PayloadVer())
			pkt.TransportCode1, pkt.TransportCode2 = 0xffff, 0xffff

			NewRegionFromHashtag(tt.region).ScopeFlood(pkt)

			got, err := pkt.ToBytes()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, wire) {
				t.Errorf("ScopeFlood gave\n%x\nthe firmware sent\n%x", got, wire)
			}
		})
	}
}

func TestRegion_ScopeFlood(t *testing.T) {
	r := NewRegionFromHashtag("sco")
	pkt := &Packet{
		Header:     MakeHeader(RouteTypeFlood, PayloadTypeGrpTxt, 1),
		PathLength: 0x40,
		Payload:    []byte{0x11, 0x22, 0x33},
	}
	r.ScopeFlood(pkt)
	if pkt.RouteType() != RouteTypeTransportFlood || pkt.PayloadType() != PayloadTypeGrpTxt || pkt.PayloadVer() != 1 {
		t.Errorf("header 0x%02x, want a transport flood keeping payload type and version", pkt.Header)
	}
	if !r.MatchesPacket(pkt) || pkt.TransportCode2 != 0 {
		t.Errorf("codes %04x %04x, want code 1 for the region and code 2 zero", pkt.TransportCode1, pkt.TransportCode2)
	}
	if pkt.PathLength != 0x40 {
		t.Errorf("path length 0x%02x changed", pkt.PathLength)
	}
}
