package openhop

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"
)

// fakeSession is one connection as the modem sees it.
type fakeSession struct {
	conn net.Conn
	rx   chan Frame

	mu   sync.Mutex
	auth bool
}

func (s *fakeSession) send(cmd byte, payload []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, _ = s.conn.Write(EncodeFrame(cmd, payload))
}

func (s *fakeSession) sendError(code byte) { s.send(CmdError, []byte{code}) }

func (s *fakeSession) authenticated() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.auth
}

func (s *fakeSession) setAuthenticated() {
	s.mu.Lock()
	s.auth = true
	s.mu.Unlock()
}

// waitFor returns the next frame carrying cmd, failing the test on timeout.
func (s *fakeSession) waitFor(t *testing.T, cmd byte) Frame {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case f, ok := <-s.rx:
			if !ok {
				t.Fatalf("session closed while waiting for 0x%02X", cmd)
			}
			if f.Cmd == cmd {
				return f
			}
		case <-deadline:
			t.Fatalf("timed out waiting for cmd 0x%02X", cmd)
		}
	}
}

// fakeModem answers the wire protocol the way the firmware does, with hooks for
// the behaviour a test wants to script.
type fakeModem struct {
	t *testing.T

	mu       sync.Mutex
	sessions []*fakeSession
	dials    int
	config   RadioConfig
	cadBusy  int  // channel reads busy for this many scans
	txBusy   int  // transmissions refused with ERR_CHANNEL_BUSY
	txFail   bool // answer TX_REQUEST with TX_FAIL
	txSilent bool // ignore TX_REQUEST entirely
	// statusFail answers the single-status-byte commands with a failure, and
	// truncate answers every query with a payload one byte short.
	statusFail bool
	truncate   bool
	dialErr    error

	airtimeUs uint32
	token     string
	connected chan *fakeSession
}

func newFakeModem(t *testing.T) *fakeModem {
	f := &fakeModem{t: t, airtimeUs: 123_456, connected: make(chan *fakeSession, 8)}
	t.Cleanup(func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, s := range f.sessions {
			_ = s.conn.Close()
		}
	})
	return f
}

func (f *fakeModem) dialer() Dialer {
	return func(_ context.Context) (io.ReadWriteCloser, error) {
		f.mu.Lock()
		f.dials++
		err := f.dialErr
		f.mu.Unlock()
		if err != nil {
			return nil, err
		}

		host, modem := net.Pipe()
		s := &fakeSession{conn: modem, rx: make(chan Frame, 64)}
		f.mu.Lock()
		f.sessions = append(f.sessions, s)
		f.mu.Unlock()
		go f.serve(s)
		select {
		case f.connected <- s:
		default:
		}
		return host, nil
	}
}

// session waits for the next connection the modem accepts.
func (f *fakeModem) session(t *testing.T) *fakeSession {
	t.Helper()
	select {
	case s := <-f.connected:
		return s
	case <-time.After(2 * time.Second):
		t.Fatal("modem never connected")
		return nil
	}
}

func (f *fakeModem) dialCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.dials
}

func (f *fakeModem) lastConfig() RadioConfig {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.config
}

func (f *fakeModem) serve(s *fakeSession) {
	defer close(s.rx)
	var p parser
	buf := make([]byte, 512)
	for {
		n, err := s.conn.Read(buf)
		if n > 0 {
			frames, _ := p.feed(buf[:n])
			for _, frame := range frames {
				s.rx <- frame
				f.answer(s, frame)
			}
		}
		if err != nil {
			return
		}
	}
}

func (f *fakeModem) answer(s *fakeSession, frame Frame) {
	f.mu.Lock()
	token, truncate := f.token, f.truncate
	f.mu.Unlock()

	if truncate {
		f.answerTruncated(s, frame)
		return
	}

	// The firmware refuses every other command until a client with a token
	// configured has authenticated, and drops the connection.
	if token != "" && !s.authenticated() && frame.Cmd != CmdAuth {
		s.sendError(ErrCodeUnauthorized)
		_ = s.conn.Close()
		return
	}

	switch frame.Cmd {
	case CmdAuth:
		if string(frame.Payload) == token {
			s.setAuthenticated()
			s.send(CmdAuthOK, nil)
			return
		}
		s.sendError(ErrCodeUnauthorized)
		_ = s.conn.Close()

	case CmdPing:
		s.send(CmdPong, nil)

	case CmdSetConfig:
		cfg, err := ParseRadioConfig(frame.Payload)
		if err != nil {
			s.sendError(ErrCodeInvalidConfig)
			return
		}
		f.mu.Lock()
		f.config = cfg
		f.mu.Unlock()
		s.send(CmdConfigResp, frame.Payload)

	case CmdGetConfig:
		cfg := f.lastConfig()
		s.send(CmdConfigResp, cfg.ToBytes())

	case CmdSetCADParams:
		s.send(CmdCADParamsResp, frame.Payload)

	case CmdSetAutoCAD, CmdSetDisplayName, CmdRadioStandby, CmdRadioResume:
		f.mu.Lock()
		status := boolByte(f.statusFail)
		f.mu.Unlock()
		s.send(map[byte]byte{
			CmdSetAutoCAD:     CmdSetAutoCADResp,
			CmdSetDisplayName: CmdSetDisplayNameResp,
			CmdRadioStandby:   CmdRadioStandbyResp,
			CmdRadioResume:    CmdRadioResumeResp,
		}[frame.Cmd], []byte{status})

	case CmdRxStart:
		s.send(CmdRxStarted, nil)

	case CmdCADRequest:
		f.mu.Lock()
		busy := f.cadBusy > 0
		if busy {
			f.cadBusy--
		}
		f.mu.Unlock()
		s.send(CmdCADResp, []byte{boolByte(busy)})

	case CmdTxRequest:
		f.mu.Lock()
		silent, fail := f.txSilent, f.txFail
		busy := f.txBusy > 0
		if busy {
			f.txBusy--
		}
		airtime := f.airtimeUs
		f.mu.Unlock()
		switch {
		case silent:
		case busy:
			s.sendError(ErrCodeChannelBusy)
		case fail:
			s.send(CmdTxFail, nil)
		default:
			s.send(CmdTxDone, binary.LittleEndian.AppendUint32(nil, airtime))
		}

	case CmdStatusReq:
		s.send(CmdStatusResp, statusPayload(true))

	case CmdNoiseReq:
		s.send(CmdNoiseResp, binary.LittleEndian.AppendUint16(nil, uint16(0xFB9C)))

	case CmdGetVersion:
		s.send(CmdVersionResp, []byte("v1.3.0-heltec_v3"))

	case CmdGetDebug:
		s.send(CmdDebugResp, make([]byte, debugRespSize))

	case CmdGetWiFi, CmdSetWiFi:
		s.send(CmdWiFiStatus, wifiPayload("modem-ab12cd"))

	case CmdWiFiReset:
		s.send(CmdWiFiReset, nil)

	case CmdEnterBootloader, CmdOTAAbort:
		s.send(CmdPong, nil)

	case CmdOTABegin:
		s.send(CmdOTABeginResp, []byte{byte(OTAUnsupported)})

	case CmdOTAChunk:
		s.send(CmdOTAChunkResp, []byte{byte(OTAChunkBadOffset)})

	case CmdOTAVerify:
		s.send(CmdOTAVerifyResp, make([]byte, 33))

	case CmdOTAApply:
		s.send(CmdOTAApplyResp, []byte{1})

	default:
		s.sendError(ErrCodeInvalidCmd)
	}
}

// answerTruncated answers every query with a payload one byte too short, for
// the paths that have to reject a malformed response.
func (f *fakeModem) answerTruncated(s *fakeSession, frame Frame) {
	switch frame.Cmd {
	case CmdGetConfig, CmdSetConfig:
		s.send(CmdConfigResp, make([]byte, RadioConfigSize-1))
	case CmdStatusReq:
		s.send(CmdStatusResp, make([]byte, statusRespSize-1))
	case CmdNoiseReq:
		s.send(CmdNoiseResp, []byte{0x01})
	case CmdGetDebug:
		s.send(CmdDebugResp, make([]byte, debugRespSize-1))
	case CmdCADRequest:
		s.send(CmdCADResp, nil)
	case CmdGetWiFi, CmdSetWiFi:
		s.send(CmdWiFiStatus, []byte{0x02})
	case CmdOTABegin:
		s.send(CmdOTABeginResp, nil)
	case CmdOTAVerify:
		s.send(CmdOTAVerifyResp, []byte{0})
	case CmdPing:
		s.send(CmdPong, nil)
	}
}

// testRadio is a configuration every test connects with.
func testRadio() RadioConfig {
	return RadioConfig{
		FreqHz: 869_618_000, BandwidthHz: 62_500, SF: 8, CR: 8,
		TxPower: 22, SyncWord: 0x12, PreambleLen: 16,
	}
}

// connect brings up a modem against the fake and registers its shutdown.
func connect(t *testing.T, f *fakeModem, cfg Config, opts ...Option) *Modem {
	t.Helper()
	if cfg.Radio == (RadioConfig{}) {
		cfg.Radio = testRadio()
	}
	opts = append([]Option{WithLogger(slog.New(slog.DiscardHandler))}, opts...)
	m := New(f.dialer(), cfg, opts...)
	t.Cleanup(func() { _ = m.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := m.Connect(ctx); err != nil {
		t.Fatalf("connect: %v", err)
	}
	return m
}
