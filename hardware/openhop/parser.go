package openhop

import (
	"encoding/binary"
	"fmt"
)

// Frame is one decoded protocol frame.
type Frame struct {
	Cmd     byte
	Payload []byte
}

// parser reassembles frames from a byte stream, resynchronising on the sync
// byte after corruption.
type parser struct {
	buf []byte
}

// feed appends data and returns every frame that completed, along with the
// decode errors seen on the way.
func (p *parser) feed(data []byte) ([]Frame, []error) {
	p.buf = append(p.buf, data...)

	var frames []Frame
	var errs []error
	for {
		// Discard anything before the next sync byte.
		start := -1
		for i, b := range p.buf {
			if b == Sync {
				start = i
				break
			}
		}
		if start < 0 {
			p.buf = p.buf[:0]
			return frames, errs
		}
		p.buf = p.buf[start:]

		if len(p.buf) < 4 {
			return frames, errs
		}
		cmd := p.buf[1]
		length := int(binary.LittleEndian.Uint16(p.buf[2:4]))
		if length > maxFramePayload {
			errs = append(errs, fmt.Errorf("openhop: frame length %d exceeds %d, resyncing", length, maxFramePayload))
			p.buf = p.buf[1:]
			continue
		}
		size := 4 + length + 2
		if len(p.buf) < size {
			return frames, errs
		}

		want := binary.LittleEndian.Uint16(p.buf[4+length : size])
		if got := CRC16CCITT(p.buf[1 : 4+length]); got != want {
			// Drop only the sync byte: the mismatch may be a payload byte we
			// mistook for a frame start, and a real frame can follow inside
			// what this length field claimed.
			errs = append(errs, fmt.Errorf("openhop: crc mismatch on cmd 0x%02X: got 0x%04X want 0x%04X", cmd, got, want))
			p.buf = p.buf[1:]
			continue
		}

		payload := make([]byte, length)
		copy(payload, p.buf[4:4+length])
		frames = append(frames, Frame{Cmd: cmd, Payload: payload})
		p.buf = p.buf[size:]
	}
}

// reset drops any partial frame, for use after a reconnect.
func (p *parser) reset() { p.buf = p.buf[:0] }
