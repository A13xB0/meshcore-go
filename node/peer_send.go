package node

import (
	"encoding/binary"
	"fmt"
	"time"

	meshcore "github.com/meshcore-go/meshcore-go"
)

// Sent reports how a send to a peer went out and how long to wait for its reply.
type Sent struct {
	Flood   bool
	Timeout time.Duration
}

// TextSent is a text message sent once; AckCRC is 0 for CLI data, which is never acked.
type TextSent struct {
	Sent
	AckCRC uint32
}

// route makes pkt a direct send along path, or a flood from this node when path is nil.
func (n *Node) route(pkt *meshcore.Packet, path []byte, pathHashSize uint8, opts []SendOption) error {
	if pathHashSize == 0 || pathHashSize > 3 {
		return fmt.Errorf("path hash size %d, want 1-3", pathHashSize)
	}
	pkt.PathLength = (pathHashSize - 1) << 6
	if path == nil {
		n.makeFlood(pkt, opts)
		return nil
	}
	hops := len(path) / int(pathHashSize)
	if len(path)%int(pathHashSize) != 0 || len(path) > meshcore.MaxPathSize || hops > 63 {
		return fmt.Errorf("path of %d bytes is not whole %d-byte hashes within %d bytes", len(path), pathHashSize, meshcore.MaxPathSize)
	}
	pkt.Header = meshcore.MakeHeader(meshcore.RouteTypeDirect, pkt.PayloadType(), pkt.PayloadVer())
	pkt.TransportCode1, pkt.TransportCode2 = 0, 0
	pkt.Path = path
	pkt.PathLength |= uint8(hops)
	return nil
}

// SendToPeer sends pkt once, direct along path or, when path is nil, as a scoped flood, with the firmware's reply timeout.
func (n *Node) SendToPeer(pkt *meshcore.Packet, path []byte, pathHashSize uint8, opts ...SendOption) (Sent, error) {
	sent, err := n.prepareToPeer(pkt, path, pathHashSize, opts)
	if err != nil {
		return Sent{}, err
	}
	return sent, n.SendPacket(pkt)
}

func (n *Node) prepareToPeer(pkt *meshcore.Packet, path []byte, pathHashSize uint8, opts []SendOption) (Sent, error) {
	if err := n.route(pkt, path, pathHashSize, opts); err != nil {
		return Sent{}, err
	}
	data, err := pkt.ToBytes()
	if err != nil {
		return Sent{}, err
	}
	airtime := n.estAirtime(len(data))
	if path == nil {
		return Sent{Flood: true, Timeout: CalcFloodTimeout(airtime)}, nil
	}
	return Sent{Timeout: CalcDirectTimeout(airtime, pkt.PathHashCount())}, nil
}

// SendTextOnce sends a plain or CLI text message once, leaving retries to the caller; onResult, if set, hears the ACK or its timeout.
func (n *Node) SendTextOnce(
	peer meshcore.Identity,
	txtType byte,
	attempt int,
	timestamp time.Time,
	text []byte,
	path []byte,
	pathHashSize uint8,
	onResult func(DMSendResult),
	opts ...SendOption,
) (TextSent, error) {
	const txtTypePlain, txtTypeCLIData = 0, 1
	if txtType != txtTypePlain && txtType != txtTypeCLIData {
		return TextSent{}, fmt.Errorf("text type %d cannot be sent", txtType)
	}
	if attempt < 0 || attempt > 255 {
		return TextSent{}, fmt.Errorf("attempt %d out of range", attempt)
	}
	limit := meshcore.MaxTextLen
	if txtType == txtTypePlain && attempt > 3 {
		limit -= 2 // the attempt rides after the text's NUL
	}
	if len(text) > limit {
		return TextSent{}, fmt.Errorf("text is %d bytes, max %d", len(text), limit)
	}
	if txtType == txtTypeCLIData {
		attempt &= 0x03
	}

	secret, err := n.secrets.get(peer)
	if err != nil {
		return TextSent{}, err
	}
	self := n.Identity()
	plaintext := meshcore.BuildTextPlaintextWithAttempt(timestamp, txtType<<2, text, attempt)
	msg, err := meshcore.NewTextMessage(self, peer, plaintext, secret)
	if err != nil {
		return TextSent{}, err
	}
	payload, err := msg.ToBytes()
	if err != nil {
		return TextSent{}, err
	}
	pkt := &meshcore.Packet{Header: meshcore.MakeHeader(meshcore.RouteTypeFlood, meshcore.PayloadTypeTxtMsg, 0), Payload: payload}
	sent, err := n.prepareToPeer(pkt, path, pathHashSize, opts)
	if err != nil {
		return TextSent{}, err
	}

	out := TextSent{Sent: sent}
	if txtType == txtTypePlain {
		out.AckCRC = meshcore.CalcAckHash(textAckHashInput(plaintext, len(text)), self.PublicKeyBytes())
		if onResult != nil {
			n.acks.expect(out.AckCRC, sent.Timeout,
				func(rt time.Duration) { onResult(DMSendResult{Confirmed: true, RoundTrip: rt}) },
				func() { onResult(DMSendResult{Confirmed: false}) },
			)
		}
	}
	if err := n.SendPacket(pkt); err != nil {
		if out.AckCRC != 0 && onResult != nil {
			n.acks.cancel(out.AckCRC)
		}
		return TextSent{}, err
	}
	return out, nil
}

func requestPlaintext(tag uint32, data []byte) ([]byte, error) {
	if len(data) > meshcore.MaxPacketPayload-16 {
		return nil, fmt.Errorf("request data is %d bytes, max %d", len(data), meshcore.MaxPacketPayload-16)
	}
	return append(binary.LittleEndian.AppendUint32(nil, tag), data...), nil
}

// SendRequest sends data to peer as a request led by tag, which its response carries back.
func (n *Node) SendRequest(peer meshcore.Identity, tag uint32, data []byte, path []byte, pathHashSize uint8, opts ...SendOption) (Sent, error) {
	plaintext, err := requestPlaintext(tag, data)
	if err != nil {
		return Sent{}, err
	}
	secret, err := n.secrets.get(peer)
	if err != nil {
		return Sent{}, err
	}
	req, err := meshcore.NewRequest(n.Identity(), peer, plaintext, secret)
	if err != nil {
		return Sent{}, err
	}
	payload, err := req.ToBytes()
	if err != nil {
		return Sent{}, err
	}
	return n.SendToPeer(&meshcore.Packet{Header: meshcore.MakeHeader(meshcore.RouteTypeFlood, meshcore.PayloadTypeReq, 0), Payload: payload}, path, pathHashSize, opts...)
}

// SendAnonRequest sends data led by tag to a peer that need not know this node yet, as logins are sent.
func (n *Node) SendAnonRequest(peer meshcore.Identity, tag uint32, data []byte, path []byte, pathHashSize uint8, opts ...SendOption) (Sent, error) {
	plaintext, err := requestPlaintext(tag, data)
	if err != nil {
		return Sent{}, err
	}
	secret, err := n.secrets.get(peer)
	if err != nil {
		return Sent{}, err
	}
	req, err := meshcore.NewAnonReq(n.Identity(), peer, plaintext, secret)
	if err != nil {
		return Sent{}, err
	}
	payload, err := req.ToBytes()
	if err != nil {
		return Sent{}, err
	}
	return n.SendToPeer(&meshcore.Packet{Header: meshcore.MakeHeader(meshcore.RouteTypeFlood, meshcore.PayloadTypeAnonReq, 0), Payload: payload}, path, pathHashSize, opts...)
}

// SendGroupData sends a datagram on a channel, direct along path or, when path is nil, as a scoped flood.
func (n *Node) SendGroupData(ch *meshcore.ChannelEntry, dataType uint16, data []byte, path []byte, pathHashSize uint8, opts ...SendOption) error {
	gd, err := meshcore.NewGroupData(ch.Hash, ch.PSK[:], dataType, data)
	if err != nil {
		return err
	}
	payload, err := gd.ToBytes()
	if err != nil {
		return err
	}
	_, err = n.SendToPeer(&meshcore.Packet{Header: meshcore.MakeHeader(meshcore.RouteTypeFlood, meshcore.PayloadTypeGrpData, 0), Payload: payload}, path, pathHashSize, opts...)
	return err
}
