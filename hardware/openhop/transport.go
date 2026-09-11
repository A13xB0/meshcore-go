package openhop

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"go.bug.st/serial"
)

// DefaultTCPPort is the port the firmware serves the protocol on.
const DefaultTCPPort = 5055

// DefaultBaudRate is the USB-CDC and protocol-UART baud rate the firmware uses.
const DefaultBaudRate = 921600

// DefaultConnectTimeout bounds one dial attempt.
const DefaultConnectTimeout = 5 * time.Second

// DefaultTCPIdleTimeout is how long a TCP link may stay silent before its read
// fails and the modem reconnects. The modem is not required to send anything
// when idle, so keep it well above the caller's own polling interval.
const DefaultTCPIdleTimeout = 60 * time.Second

// DefaultTCPWriteTimeout bounds a single write's wait on the send buffer.
const DefaultTCPWriteTimeout = 10 * time.Second

// serialReadTimeout keeps serial reads short so a Close is noticed promptly.
const serialReadTimeout = 100 * time.Millisecond

// Dialer opens one connection to the modem. It is called again for every
// reconnection, so it must be reusable.
type Dialer func(ctx context.Context) (io.ReadWriteCloser, error)

// TCPDialer connects to a networked modem. A zero idle timeout uses
// DefaultTCPIdleTimeout; a negative one disables the deadline.
func TCPDialer(address string, idleTimeout time.Duration) Dialer {
	idle := resolveTimeout(idleTimeout, DefaultTCPIdleTimeout)
	return func(ctx context.Context) (io.ReadWriteCloser, error) {
		var d net.Dialer
		conn, err := d.DialContext(ctx, "tcp", address)
		if err != nil {
			return nil, fmt.Errorf("openhop: dial tcp %s: %w", address, err)
		}
		if tcp, ok := conn.(*net.TCPConn); ok {
			// The firmware sets TCP_NODELAY on its side; command latency
			// matters more here than packing small frames.
			_ = tcp.SetNoDelay(true)
		}
		return &deadlineConn{Conn: conn, idle: idle, write: DefaultTCPWriteTimeout}, nil
	}
}

// SerialDialer opens a USB-CDC or protocol-UART link. A zero baud rate uses
// DefaultBaudRate.
func SerialDialer(port string, baudRate int) Dialer {
	if baudRate == 0 {
		baudRate = DefaultBaudRate
	}
	return func(_ context.Context) (io.ReadWriteCloser, error) {
		p, err := serial.Open(port, &serial.Mode{BaudRate: baudRate})
		if err != nil {
			return nil, fmt.Errorf("openhop: open serial port %s: %w", port, err)
		}
		if err := p.SetReadTimeout(serialReadTimeout); err != nil {
			_ = p.Close()
			return nil, fmt.Errorf("openhop: set serial read timeout: %w", err)
		}
		return p, nil
	}
}

func resolveTimeout(v, def time.Duration) time.Duration {
	switch {
	case v == 0:
		return def
	case v < 0:
		return 0
	default:
		return v
	}
}

// deadlineConn applies per-operation deadlines, so a silent link fails instead
// of blocking the read loop forever.
type deadlineConn struct {
	net.Conn
	idle  time.Duration
	write time.Duration
}

func (c *deadlineConn) Read(p []byte) (int, error) {
	if c.idle > 0 {
		if err := c.SetReadDeadline(time.Now().Add(c.idle)); err != nil {
			return 0, err
		}
	}
	return c.Conn.Read(p)
}

func (c *deadlineConn) Write(p []byte) (int, error) {
	if c.write > 0 {
		if err := c.SetWriteDeadline(time.Now().Add(c.write)); err != nil {
			return 0, err
		}
		defer func() { _ = c.SetWriteDeadline(time.Time{}) }()
	}
	return c.Conn.Write(p)
}
