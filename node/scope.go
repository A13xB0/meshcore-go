package node

import (
	meshcore "github.com/meshcore-go/meshcore-go"
)

type sendOptions struct {
	scope    *meshcore.Region
	scopeSet bool
}

// SendOption adjusts a single send.
type SendOption func(*sendOptions)

// InScope floods this send inside r; a nil r sends it unscoped.
func InScope(r *meshcore.Region) SendOption {
	return func(o *sendOptions) { o.scope, o.scopeSet = r, true }
}

// Unscoped floods this send with no region, whatever the node's flood scope.
func Unscoped() SendOption { return InScope(nil) }

// WithFloodScope sets the region the floods this node originates go out in, until a send says otherwise.
func WithFloodScope(r *meshcore.Region) Option {
	return func(c *nodeConfig) { c.floodScope = r }
}

// SetFloodScope changes the node's flood scope; nil floods unscoped.
func (n *Node) SetFloodScope(r *meshcore.Region) {
	n.floodScope.Store(r)
}

func (n *Node) FloodScope() *meshcore.Region {
	return n.floodScope.Load()
}

func (n *Node) scopeFor(opts []SendOption) *meshcore.Region {
	var o sendOptions
	for _, opt := range opts {
		opt(&o)
	}
	if o.scopeSet {
		return o.scope
	}
	return n.FloodScope()
}

// makeFlood turns pkt into a flood from this node with no hops yet, keeping its path hash size, scoped as opts say.
func (n *Node) makeFlood(pkt *meshcore.Packet, opts []SendOption) {
	pkt.Header = meshcore.MakeHeader(meshcore.RouteTypeFlood, pkt.PayloadType(), pkt.PayloadVer())
	pkt.TransportCode1, pkt.TransportCode2 = 0, 0
	pkt.PathLength &= 0xc0
	pkt.Path = []byte{}
	if r := n.scopeFor(opts); r != nil {
		r.ScopeFlood(pkt)
	}
}

// SendFlood sends pkt as a flood this node originates, in the node's flood scope unless opts say otherwise.
func (n *Node) SendFlood(pkt *meshcore.Packet, opts ...SendOption) error {
	n.makeFlood(pkt, opts)
	return n.SendPacket(pkt)
}
