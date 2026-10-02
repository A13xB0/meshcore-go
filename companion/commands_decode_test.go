package companion

import (
	"bytes"
	"errors"
	"go/ast"
	goparser "go/parser"
	"go/token"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func seq(n int, start byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}

func roundTripCommands() []Command {
	key := key32(seq(32, 0x10))
	var prefix [6]byte
	copy(prefix[:], key[:6])
	var priv [64]byte
	copy(priv[:], seq(64, 0x40))
	var secret [16]byte
	copy(secret[:], seq(16, 0xa0))
	advert := seq(110, 0x01)

	return []Command{
		AppStartCommand{AppVersion: 3, AppName: "MeshCore App"},
		AppStartCommand{},
		SendTxtMsgCommand{TxtType: TxtTypePlain, Attempt: 2, SenderTimestamp: 1790897222, PubKeyPrefix: prefix, Text: "hello mesh"},
		SendChannelTxtMsgCommand{TxtType: TxtTypePlain, ChannelIdx: 3, SenderTimestamp: 1790897222, Text: "weather for fife"},
		GetContactsCommand{},
		GetContactsCommand{Since: 1790000000, HasSince: true},
		GetDeviceTimeCommand{},
		SetDeviceTimeCommand{EpochSecs: 1790897222},
		SendSelfAdvertCommand{},
		SendSelfAdvertCommand{Flood: true},
		SetAdvertNameCommand{Name: "Cadham Village"},
		AddUpdateContactCommand{PublicKey: key, Type: 2, Flags: 1, OutPathLen: 0x42, OutPath: seq(4, 0x90), Name: "Fife Rptr", LastAdvert: 7, Latitude: 56017000, Longitude: -3449000, LastModified: 9},
		AddUpdateContactCommand{PublicKey: key, Type: 1, OutPathLen: OutPathUnknown, Name: "Amy", OmitLocation: true},
		AddUpdateContactCommand{PublicKey: key, Type: 1, Latitude: -1, Longitude: 1, OmitLastModified: true},
		SyncNextMessageCommand{},
		SetRadioParamsCommand{Frequency: 869618, Bandwidth: 62500, SpreadFactor: 8, CodingRate: 8},
		SetRadioParamsCommand{Frequency: 869618, Bandwidth: 62500, SpreadFactor: 8, CodingRate: 8, ClientRepeat: true},
		SetTxPowerCommand{TxPower: 22},
		ResetPathCommand{PublicKey: key},
		SetAdvertLatLonCommand{Latitude: 56205568, Longitude: -3161287},
		SetAdvertLatLonCommand{Latitude: 1, Longitude: 2, Altitude: -3, HasAltitude: true},
		RemoveContactCommand{PublicKey: key},
		ShareContactCommand{PublicKey: key},
		ExportContactCommand{PublicKey: key},
		ExportContactCommand{Self: true},
		ImportContactCommand{AdvertData: advert},
		RebootCommand{},
		GetBattAndStorageCommand{},
		SetTuningParamsCommand{RxDelayBase: 0.5, AirtimeFactor: 1.25},
		DeviceQueryCommand{AppTargetVersion: 3},
		ExportPrivateKeyCommand{},
		ImportPrivateKeyCommand{PrivateKey: priv},
		SendRawDataCommand{Path: seq(2, 0x70), RawData: seq(8, 0x30)},
		SendRawDataCommand{RawData: seq(4, 0x30)},
		SendLoginCommand{PublicKey: key, Password: "hunter2"},
		SendLoginCommand{PublicKey: key},
		SendStatusReqCommand{PublicKey: key},
		HasConnectionCommand{PublicKey: key},
		LogoutCommand{PublicKey: key},
		GetContactByKeyCommand{PublicKey: key},
		GetChannelCommand{ChannelIdx: 7},
		SetChannelCommand{ChannelIdx: 1, Name: "#scotland", Secret: secret},
		SignStartCommand{},
		SignDataCommand{Data: seq(40, 0x00)},
		SignFinishCommand{},
		SendTracePathCommand{Tag: 0xdeadbeef, Auth: 0x01020304, Flags: 1, Path: seq(6, 0x20)},
		SetDevicePinCommand{Pin: 123456},
		SetOtherParamsCommand{ManualAddContacts: 1},
		SetOtherParamsCommand{ManualAddContacts: 1, HasTelemetryModes: true, TelemetryModeBase: 2, TelemetryModeLocation: 1, TelemetryModeEnvironment: 3},
		SetOtherParamsCommand{HasTelemetryModes: true, HasAdvertLocPolicy: true, AdvertLocPolicy: 1},
		SetOtherParamsCommand{HasTelemetryModes: true, HasAdvertLocPolicy: true, HasMultiAcks: true, MultiAcks: 2},
		SendTelemetryReqCommand{PublicKey: key},
		SendTelemetryReqCommand{Self: true},
		GetCustomVarsCommand{},
		SetCustomVarCommand{Name: "gps", Value: "1"},
		SetCustomVarCommand{Name: "gps_interval", Value: ""},
		GetAdvertPathCommand{PublicKey: key},
		GetTuningParamsCommand{},
		SendBinaryReqCommand{PublicKey: key, RequestData: seq(9, 0x05)},
		FactoryResetCommand{},
		SendPathDiscoveryReqCommand{PublicKey: key},
		SetFloodScopeCommand{TransportKey: seq(16, 0x60)},
		SetFloodScopeCommand{},
		SetFloodScopeCommand{Unscoped: true},
		SendControlDataCommand{ControlData: []byte{0x80, 0x01, 0x02}},
		GetStatsCommand{StatsType: StatsTypeRadio},
		SendAnonReqCommand{PublicKey: key, RequestData: seq(5, 0x01)},
		SetAutoAddConfigCommand{Config: AutoAddChat | AutoAddRepeater, MaxHops: 3},
		SetAutoAddConfigCommand{Config: AutoAddOverwriteOldest, OmitMaxHops: true},
		GetAutoAddConfigCommand{},
		GetAllowedRepeatFreqCommand{},
		SetPathHashModeCommand{Mode: 2},
		SendChannelDataCommand{ChannelIdx: 0, Flood: true, DataType: 0x0102, Payload: seq(12, 0x00)},
		SendChannelDataCommand{ChannelIdx: 2, PathLen: 0x42, Path: seq(4, 0x50), DataType: 7},
		SetDefaultFloodScopeCommand{Name: "sco", Key: seq(16, 0xc0)},
		SetDefaultFloodScopeCommand{},
		GetDefaultFloodScopeCommand{},
		SendRawPacketCommand{Priority: 1, Packet: seq(20, 0x11)},
	}
}

func TestParseCommandRoundTrip(t *testing.T) {
	for _, want := range roundTripCommands() {
		name := reflect.TypeOf(want).Name()
		t.Run(name, func(t *testing.T) {
			frame := want.ToBytes()
			got, err := ParseCommand(frame)
			if err != nil {
				t.Fatalf("ParseCommand(% x) error: %v", frame, err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("ParseCommand(% x)\n got %#v\nwant %#v", frame, got, want)
			}
			if again := got.ToBytes(); !bytes.Equal(again, frame) {
				t.Errorf("re-encoded % x, want % x", again, frame)
			}
		})
	}
}

// commandCodes reads every Cmd* constant from constants.go, so a new code without a decoder fails here.
func commandCodes(t *testing.T) map[string]byte {
	t.Helper()
	file, err := goparser.ParseFile(token.NewFileSet(), "constants.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	codes := map[string]byte{}
	ast.Inspect(file, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok || len(vs.Names) != 1 || len(vs.Values) != 1 || !strings.HasPrefix(vs.Names[0].Name, "Cmd") {
			return true
		}
		lit, ok := vs.Values[0].(*ast.BasicLit)
		if !ok {
			return true
		}
		v, err := strconv.ParseUint(lit.Value, 0, 8)
		if err != nil {
			t.Fatalf("%s = %s: %v", vs.Names[0].Name, lit.Value, err)
		}
		codes[vs.Names[0].Name] = byte(v)
		return true
	})
	return codes
}

func TestParseCommandCoversEveryCode(t *testing.T) {
	covered := map[byte]bool{}
	for _, c := range roundTripCommands() {
		covered[c.ToBytes()[0]] = true
	}
	codes := commandCodes(t)
	if len(codes) != 58 {
		t.Errorf("found %d Cmd* constants, want the firmware's 58", len(codes))
	}
	for name, code := range codes {
		if _, ok := commandParsers[code]; !ok {
			t.Errorf("%s (%d) has no decoder", name, code)
		}
		if !covered[code] {
			t.Errorf("%s (%d) has no round-trip case", name, code)
		}
	}
}

func TestParseCommandFirmwareRefusals(t *testing.T) {
	key := seq(32, 0x10)
	tests := []struct {
		name    string
		frame   []byte
		errCode byte
	}{
		{"unknown command", []byte{0x2c}, ErrCodeUnsupportedCmd},
		{"app start without its reserved bytes", []byte{CmdAppStart, 3}, ErrCodeUnsupportedCmd},
		{"text message with no text", append([]byte{CmdSendTxtMsg, 0, 0, 1, 2, 3, 4}, key[:6]...), ErrCodeUnsupportedCmd},
		{"device query without a version", []byte{CmdDeviceQuery}, ErrCodeUnsupportedCmd},
		{"remove contact by 6-byte prefix", append([]byte{CmdRemoveContact}, key[:6]...), ErrCodeNotFound},
		{"reboot without the literal", []byte{CmdReboot, 'r', 'e', 'b', 'o', 'o', 'x'}, ErrCodeUnsupportedCmd},
		{"factory reset without the literal", []byte{CmdFactoryReset}, ErrCodeUnsupportedCmd},
		{"256-bit channel secret", append([]byte{CmdSetChannel, 1}, make([]byte, 64)...), ErrCodeUnsupportedCmd},
		{"channel secret cut short", append([]byte{CmdSetChannel, 1}, make([]byte, 40)...), ErrCodeUnsupportedCmd},
		{"raw data as flood", append([]byte{CmdSendRawData, 0xff}, make([]byte, 6)...), ErrCodeUnsupportedCmd},
		{"raw data under 4 bytes", []byte{CmdSendRawData, 2, 0x70, 0x71, 1, 2, 3}, ErrCodeUnsupportedCmd},
		{"trace path not whole hashes", append([]byte{CmdSendTracePath, 1, 2, 3, 4, 5, 6, 7, 8, 1}, 0x20, 0x21, 0x22), ErrCodeIllegalArg},
		{"trace with no path", []byte{CmdSendTracePath, 1, 2, 3, 4, 5, 6, 7, 8, 0}, ErrCodeUnsupportedCmd},
		{"telemetry request of odd length", []byte{CmdSendTelemetryReq, 0, 0, 0, 1}, ErrCodeUnsupportedCmd},
		{"custom var without separator", []byte{CmdSetCustomVar, 'g', 'p', 's', 0}, ErrCodeIllegalArg},
		{"path discovery with reserved byte set", append([]byte{CmdSendPathDiscoveryReq, 1}, key...), ErrCodeUnsupportedCmd},
		{"flood scope mode 2", []byte{CmdSetFloodScopeKey, 2}, ErrCodeUnsupportedCmd},
		{"control data without the top bit", []byte{CmdSendControlData, 0x01}, ErrCodeUnsupportedCmd},
		{"unknown stats type", []byte{CmdGetStats, 3}, ErrCodeIllegalArg},
		{"anon request with no data", append([]byte{CmdSendAnonReq}, key...), ErrCodeUnsupportedCmd},
		{"path hash mode 3", []byte{CmdSetPathHashMode, 0, 3}, ErrCodeIllegalArg},
		{"path hash mode with reserved byte set", []byte{CmdSetPathHashMode, 1, 1}, ErrCodeUnsupportedCmd},
		{"channel data too short", []byte{CmdSendChannelData, 0, 0xff}, ErrCodeIllegalArg},
		{"channel data with an invalid path length", []byte{CmdSendChannelData, 0, 0xc1, 0, 0}, ErrCodeIllegalArg},
		{"channel data path past the end", []byte{CmdSendChannelData, 0, 0x05, 1, 2}, ErrCodeIllegalArg},
		{"raw packet too short", []byte{CmdSendRawPacket, 0, 1}, ErrCodeUnsupportedCmd},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseCommand(tt.frame)
			var ce *CommandError
			if !errors.As(err, &ce) {
				t.Fatalf("ParseCommand(% x) error = %v, want a *CommandError", tt.frame, err)
			}
			if ce.Cmd != tt.frame[0] || ce.ErrCode != tt.errCode {
				t.Errorf("got cmd 0x%02x err code %d, want cmd 0x%02x err code %d", ce.Cmd, ce.ErrCode, tt.frame[0], tt.errCode)
			}
		})
	}
	if _, err := ParseCommand(nil); err == nil {
		t.Error("ParseCommand(nil) succeeded, want an error")
	}
}

func TestParseCommandFirmwareLayouts(t *testing.T) {
	name := append([]byte("Fife Rptr"), make([]byte, 32-9)...)
	contact := append([]byte{CmdAddUpdateContact}, seq(32, 0x10)...)
	contact = append(contact, 2, 0, 0x01, 0xaa)
	contact = append(contact, make([]byte, 63)...)
	contact = append(contact, name...)
	contact = append(contact, 1, 0, 0, 0)

	tests := []struct {
		name  string
		frame []byte
		want  Command
	}{
		{
			name:  "app start name ends at the first NUL",
			frame: []byte{CmdAppStart, 3, 0, 0, 0, 0, 0, 0, 'a', 'p', 'p', 0, 'x'},
			want:  AppStartCommand{AppVersion: 3, AppName: "app"},
		},
		{
			name:  "channel text keeps every byte the firmware sends",
			frame: []byte{CmdSendChannelTxtMsg, 0, 1, 0, 0, 0, 0, 'h', 'i'},
			want:  SendChannelTxtMsgCommand{ChannelIdx: 1, Text: "hi"},
		},
		{
			name:  "self advert without the flood byte is zero hop",
			frame: []byte{CmdSendSelfAdvert},
			want:  SendSelfAdvertCommand{},
		},
		{
			name:  "contact without location takes the 136-byte form",
			frame: contact,
			want:  AddUpdateContactCommand{PublicKey: key32(seq(32, 0x10)), Type: 2, OutPathLen: 1, OutPath: []byte{0xaa}, Name: "Fife Rptr", LastAdvert: 1, OmitLocation: true},
		},
		{
			name:  "radio params with repeat byte zero",
			frame: []byte{CmdSetRadioParams, 0xf2, 0x44, 0x0d, 0, 0x24, 0xf4, 0, 0, 8, 8, 0},
			want:  SetRadioParamsCommand{Frequency: 869618, Bandwidth: 62500, SpreadFactor: 8, CodingRate: 8},
		},
		{
			name:  "flood scope reset is a short mode 0 frame",
			frame: []byte{CmdSetFloodScopeKey, 0},
			want:  SetFloodScopeCommand{},
		},
		{
			name:  "default flood scope cleared by a bare frame",
			frame: []byte{CmdSetDefaultFloodScope},
			want:  SetDefaultFloodScopeCommand{},
		},
		{
			name:  "export with a short frame exports self",
			frame: []byte{CmdExportContact, 1, 2},
			want:  ExportContactCommand{Self: true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCommand(tt.frame)
			if err != nil {
				t.Fatalf("ParseCommand(% x) error: %v", tt.frame, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %#v\nwant %#v", got, tt.want)
			}
		})
	}
}

func FuzzParseCommand(f *testing.F) {
	for _, c := range roundTripCommands() {
		f.Add(c.ToBytes())
	}
	f.Add([]byte("\x150000X\xff\x00\x00"))
	f.Fuzz(func(t *testing.T, frame []byte) {
		c1, err := ParseCommand(frame)
		if err != nil {
			return
		}
		c2, err := ParseCommand(c1.ToBytes())
		if err != nil {
			return
		}
		c3, err := ParseCommand(c2.ToBytes())
		if err != nil {
			t.Fatalf("% x decoded once but not twice: %v", frame, err)
		}
		if !reflect.DeepEqual(c2, c3) {
			t.Fatalf("% x does not settle:\n%#v\n%#v", frame, c2, c3)
		}
	})
}
