package companion

import (
	"bytes"
	"encoding/hex"
	"go/ast"
	goparser "go/parser"
	"go/token"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func roundTripResponses() []Response {
	key := key32(seq(32, 0x10))
	var prefix [6]byte
	copy(prefix[:], key[:6])
	var outPath [64]byte
	copy(outPath[:], seq(3, 0x90))
	var secret [16]byte
	copy(secret[:], seq(16, 0xa0))
	var priv, sig [64]byte
	copy(priv[:], seq(64, 0x40))
	copy(sig[:], seq(64, 0x80))

	r := func(code byte, data any) Response { return Response{Code: code, Data: data} }
	return []Response{
		r(RespOk, OkResponse{}),
		r(RespOk, OkResponse{Value: 7, HasValue: true}),
		r(RespErr, ErrResponse{}),
		r(RespErr, ErrResponse{ErrorCode: ErrCodeNotFound, HasErrorCode: true}),
		r(RespContactsStart, ContactsStartResponse{Count: 523, HasCount: true}),
		r(RespContactsStart, ContactsStartResponse{}),
		r(RespContact, ContactResponse{PublicKey: key, Type: 2, Flags: 1, OutPathLen: 3, OutPath: outPath, AdvertName: "Fife Rptr", LastAdvert: 1790897222, AdvertLatitude: 56017000, AdvertLongitude: -3449000, LastModified: 1790897300}),
		r(RespEndOfContacts, EndOfContactsResponse{MostRecentLastmod: 1790897300}),
		r(RespSelfInfo, SelfInfoResponse{AdvertType: 1, TxPower: 22, MaxTxPower: 22, PublicKey: key, AdvertLatitude: 56205568, AdvertLongitude: -3161287, Reserved: [3]byte{1, 0, 0x15}, ManualAddContacts: 1, RadioFrequency: 869618, RadioBandwidth: 62500, RadioSpreadFactor: 8, RadioCodingRate: 8, Name: "Alex 🏠"}),
		r(RespSent, SentResponse{IsFlood: true, Tag: 0xa1b2c3d4, EstTimeout: 7900, HasExtended: true}),
		r(RespSent, SentResponse{AckCode: 0x01020304, HasAckCode: true}),
		r(RespSent, SentResponse{}),
		r(RespContactMsgRecv, ContactMsgRecvResponse{PubKeyPrefix: prefix, PathLen: 2, TxtType: TxtTypePlain, SenderTimestamp: 1790897222, Text: "hi"}),
		r(RespContactMsgRecv, ContactMsgRecvResponse{PubKeyPrefix: prefix, PathLen: 0xff, TxtType: TxtTypeSignedPlain, SenderPrefix: []byte{1, 2, 3, 4}, SenderTimestamp: 5, Text: "room post"}),
		r(RespChannelMsgRecv, ChannelMsgRecvResponse{ChannelIdx: 3, PathLen: 1, TxtType: TxtTypePlain, SenderTimestamp: 9, Text: "Scot: hello"}),
		r(RespCurrTime, CurrTimeResponse{Timestamp: 1790897222}),
		r(RespNoMoreMessages, NoMoreMessagesResponse{}),
		r(RespExportContact, ExportContactResponse{AdvertData: seq(110, 0x01)}),
		r(RespBattAndStorage, BattAndStorageResponse{BatteryMilliVolts: 4012, UsedStorageKB: 85, TotalStorageKB: 1024}),
		r(RespDeviceInfo, DeviceInfoResponse{FirmwareVersion: 13, MaxContacts: 350, MaxChannels: 40, BLEPin: 123456, FirmwareBuildDate: "30 Sep 2026", Model: "OwlShack", FirmwareVersionStr: "v1.17.1", RepeatEnabled: true, PathHashMode: 2}),
		r(RespDeviceInfo, DeviceInfoResponse{FirmwareVersion: 2}),
		r(RespPrivateKey, PrivateKeyResponse{PrivateKey: priv}),
		r(RespDisabled, DisabledResponse{}),
		r(RespContactMsgRecvV3, ContactMsgRecvV3Response{SNR: -7.25, PubKeyPrefix: prefix, PathLen: 3, TxtType: TxtTypeCLIData, SenderTimestamp: 1, Text: "> 917.375"}),
		r(RespChannelMsgRecvV3, ChannelMsgRecvV3Response{SNR: 11.5, ChannelIdx: 1, PathLen: 0x42, TxtType: TxtTypePlain, SenderTimestamp: 2, Text: "WeatherBot: dry"}),
		r(RespChannelInfo, ChannelInfoResponse{ChannelIdx: 2, Name: "#longfast", Secret: secret}),
		r(RespSignStart, SignStartResponse{MaxSignDataLen: 8 * 1024}),
		r(RespSignature, SignatureResponse{Signature: sig}),
		r(RespCustomVars, CustomVarsResponse{Vars: "gps:1,gps_interval:900"}),
		r(RespCustomVars, CustomVarsResponse{}),
		r(RespAdvertPath, AdvertPathResponse{RecvTimestamp: 3, PathLen: 0x42, Path: seq(4, 0x55)}),
		r(RespTuningParams, TuningParamsResponse{RxDelayBase: 0.5, AirtimeFactor: 1.25}),
		r(RespStats, StatsResponse{StatsType: StatsTypeCore, Core: &CoreStats{BatteryMV: 4100, UptimeSecs: 795600, ErrFlags: 2, QueueLen: 1}}),
		r(RespStats, StatsResponse{StatsType: StatsTypeRadio, Radio: &RadioStats{NoiseFloor: -112, LastRSSI: -97, LastSNR: -3.75, TxAirSecs: 1200, RxAirSecs: 86000}}),
		r(RespStats, StatsResponse{StatsType: StatsTypePackets, Packets: &PacketStats{PacketsRecv: 116495, PacketsSent: 4012, SentFlood: 3000, SentDirect: 1012, RecvFlood: 100000, RecvDirect: 16495, RecvErrors: 3539}}),
		r(RespAutoAddConfig, AutoAddConfigResponse{Config: AutoAddChat | AutoAddSensor, MaxHops: 3}),
		r(RespAllowedRepeatFreq, AllowedRepeatFreqResponse{Ranges: []FreqRange{{LowerFreq: 433000, UpperFreq: 433000}, {LowerFreq: 869400, UpperFreq: 869650}}}),
		r(RespChannelDataRecv, ChannelDataRecvResponse{SNR: 6, ChannelIdx: 0, PathLen: 0xff, DataType: 0x0102, Data: seq(20, 0x30)}),
		r(RespDefaultFloodScope, DefaultFloodScopeResponse{Name: "sco", Key: seq(16, 0xc0)}),
		r(RespDefaultFloodScope, DefaultFloodScopeResponse{}),
		r(PushAdvert, PushAdvertResponse{PublicKey: key}),
		r(PushPathUpdated, PushPathUpdatedResponse{PublicKey: key}),
		r(PushSendConfirmed, PushSendConfirmedResponse{AckCode: 0x01020304, RoundTrip: 4200}),
		r(PushMsgWaiting, PushMsgWaitingResponse{}),
		r(PushRawData, PushRawDataResponse{LastSNR: 2.25, LastRSSI: -88, Payload: seq(6, 0x01)}),
		r(PushLoginSuccess, PushLoginSuccessResponse{Permissions: 1, PubKeyPrefix: prefix, HasServerInfo: true, ServerTime: 1790897222, ACL: 3, FirmwareLevel: 2}),
		r(PushLoginSuccess, PushLoginSuccessResponse{PubKeyPrefix: prefix}),
		r(PushLoginFail, PushLoginFailResponse{PubKeyPrefix: prefix}),
		r(PushStatusResponse, PushStatusResp{PubKeyPrefix: prefix, StatusData: seq(56, 0x00)}),
		r(PushLogRxData, PushLogRxDataResponse{LastSNR: -12.5, LastRSSI: -120, Raw: seq(30, 0x11)}),
		r(PushTraceData, PushTraceDataResponse{PathLen: 4, Flags: 1, Tag: 9, AuthCode: 10, PathHashes: seq(4, 0x20), PathSnrs: []byte{0x10, 0xf0}, LastSNR: 4.5}),
		r(PushNewAdvert, PushNewAdvertResponse{PublicKey: key, Type: 3, OutPathLen: 0xff, AdvertName: "Moomin Room", LastAdvert: 1, LastModified: 2}),
		r(PushTelemetryResponse, PushTelemetryResp{PubKeyPrefix: prefix, LPPData: []byte{1, 0x74, 0x01, 0x9a}}),
		r(PushBinaryResponse, PushBinaryResp{Tag: 0xcafef00d, ResponseData: seq(12, 0x00)}),
		r(PushPathDiscoveryResponse, PushPathDiscoveryResp{PubKeyPrefix: prefix, OutPathLen: 0x42, OutPath: seq(4, 0x60), InPathLen: 1, InPath: []byte{0x70}}),
		r(PushControlData, PushControlDataResp{SNR: 9.75, RSSI: -70, PathLen: 0, Payload: []byte{0x91, 0x01, 0x02}}),
		r(PushContactDeleted, PushContactDeletedResponse{PublicKey: key}),
		r(PushContactsFull, PushContactsFullResponse{}),
	}
}

func TestResponseToBytesRoundTrip(t *testing.T) {
	for _, want := range roundTripResponses() {
		t.Run(reflect.TypeOf(want.Data).Name(), func(t *testing.T) {
			frame, err := want.ToBytes()
			if err != nil {
				t.Fatalf("ToBytes: %v", err)
			}
			if len(frame) > MaxFrameSize {
				t.Errorf("frame is %d bytes, over MaxFrameSize", len(frame))
			}
			got, err := ParseResponse(frame)
			if err != nil {
				t.Fatalf("ParseResponse(% x): %v", frame, err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("ParseResponse(% x)\n got %#v\nwant %#v", frame, got.Data, want.Data)
			}
		})
	}
}

// responseCodes reads every Resp* and Push* code constant from constants.go.
func responseCodes(t *testing.T) map[string]byte {
	t.Helper()
	file, err := goparser.ParseFile(token.NewFileSet(), "constants.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	codes := map[string]byte{}
	ast.Inspect(file, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok || len(vs.Names) != 1 || len(vs.Values) != 1 {
			return true
		}
		name := vs.Names[0].Name
		if !strings.HasPrefix(name, "Resp") && !strings.HasPrefix(name, "Push") {
			return true
		}
		lit, ok := vs.Values[0].(*ast.BasicLit)
		if !ok {
			return true
		}
		v, err := strconv.ParseUint(lit.Value, 0, 8)
		if err != nil {
			t.Fatalf("%s = %s: %v", name, lit.Value, err)
		}
		codes[name] = byte(v)
		return true
	})
	return codes
}

func TestResponseToBytesCoversEveryCode(t *testing.T) {
	covered := map[byte]bool{}
	for _, r := range roundTripResponses() {
		covered[r.Code] = true
	}
	codes := responseCodes(t)
	if len(codes) != 46 {
		t.Errorf("found %d Resp*/Push* constants, want the firmware's 46", len(codes))
	}
	for name, code := range codes {
		if !covered[code] {
			t.Errorf("%s (0x%02x) has no round-trip case", name, code)
		}
	}
}

func TestResponseToBytesFirmwareLayouts(t *testing.T) {
	var key [32]byte
	key[0], key[31] = 0x04, 0xa5
	prefix := [6]byte{0x04, 0xf1, 0xfe, 0x66, 0xa2, 0x7b}

	tests := []struct {
		name    string
		resp    interface{ ToBytes() []byte }
		wantHex string
	}{
		{
			name:    "error frame carries the error code",
			resp:    ErrResponse{ErrorCode: ErrCodeTableFull, HasErrorCode: true},
			wantHex: "0103",
		},
		{
			name: "self info",
			resp: SelfInfoResponse{AdvertType: 1, TxPower: 22, MaxTxPower: 22, PublicKey: key, AdvertLatitude: 1, AdvertLongitude: -1, Reserved: [3]byte{1, 2, 0x15}, ManualAddContacts: 1, RadioFrequency: 869618, RadioBandwidth: 62500, RadioSpreadFactor: 8, RadioCodingRate: 8, Name: "Amy"},
			wantHex: "05011616" + "04" + strings.Repeat("00", 30) + "a5" + "01000000" + "ffffffff" + "010215" + "01" +
				"f2440d00" + "24f40000" + "0808" + "416d79",
		},
		{
			name: "device info pads its strings to 12, 40 and 20 bytes",
			resp: DeviceInfoResponse{FirmwareVersion: 13, MaxContacts: 350, MaxChannels: 40, BLEPin: 123456, FirmwareBuildDate: "1 Oct 2026", Model: "OwlShack", FirmwareVersionStr: "v1.17.1", PathHashMode: 2},
			wantHex: "0d0daf28" + "40e20100" + hex.EncodeToString([]byte("1 Oct 2026")) + "0000" +
				hex.EncodeToString([]byte("OwlShack")) + strings.Repeat("00", 32) +
				hex.EncodeToString([]byte("v1.17.1")) + strings.Repeat("00", 13) + "0002",
		},
		{
			name:    "sent reply to a text message",
			resp:    SentResponse{IsFlood: true, Tag: 0x01020304, EstTimeout: 7900, HasExtended: true},
			wantHex: "060104030201dc1e0000",
		},
		{
			name:    "v3 contact message has SNR then two reserved bytes",
			resp:    ContactMsgRecvV3Response{SNR: -7.25, PubKeyPrefix: prefix, PathLen: 0xff, TxtType: TxtTypePlain, SenderTimestamp: 1, Text: "ok"},
			wantHex: "10e30000" + "04f1fe66a27b" + "ff00" + "01000000" + "6f6b",
		},
		{
			name:    "channel data reports its own length",
			resp:    ChannelDataRecvResponse{SNR: 1, ChannelIdx: 2, PathLen: 1, DataType: 0x0201, Data: []byte{0xaa, 0xbb}},
			wantHex: "1b04000002010102" + "02aabb",
		},
		{
			name:    "legacy login success stops after the key prefix",
			resp:    PushLoginSuccessResponse{PubKeyPrefix: prefix},
			wantHex: "8500" + "04f1fe66a27b",
		},
		{
			name:    "login success with server info",
			resp:    PushLoginSuccessResponse{Permissions: 1, PubKeyPrefix: prefix, HasServerInfo: true, ServerTime: 0x0a0b0c0d, ACL: 3, FirmwareLevel: 1},
			wantHex: "8501" + "04f1fe66a27b" + "0d0c0b0a" + "0301",
		},
		{
			name:    "raw data has a 0xff reserved byte",
			resp:    PushRawDataResponse{LastSNR: 2.5, LastRSSI: -90, Payload: []byte{1}},
			wantHex: "840aa6ff01",
		},
		{
			name:    "trace data",
			resp:    PushTraceDataResponse{PathLen: 2, Flags: 0, Tag: 1, AuthCode: 2, PathHashes: []byte{0xaa, 0xbb}, PathSnrs: []byte{0x10, 0x20}, LastSNR: -1},
			wantHex: "89000200" + "01000000" + "02000000" + "aabb" + "1020" + "fc",
		},
		{
			name:    "binary response leads with a reserved byte then the tag",
			resp:    PushBinaryResp{Tag: 0x01020304, ResponseData: []byte{9}},
			wantHex: "8c00" + "04030201" + "09",
		},
		{
			name:    "an empty default flood scope is the bare code",
			resp:    DefaultFloodScopeResponse{},
			wantHex: "1c",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hex.EncodeToString(tt.resp.ToBytes()); got != tt.wantHex {
				t.Errorf("ToBytes() = %s\n          want %s", got, tt.wantHex)
			}
		})
	}
}

func TestResponseToBytesCapsMessageText(t *testing.T) {
	long := strings.Repeat("é", 100)
	frame := ChannelMsgRecvV3Response{Text: long}.ToBytes()
	if len(frame) > MaxFrameSize {
		t.Fatalf("frame is %d bytes, over MaxFrameSize", len(frame))
	}
	parsed, err := ParseChannelMsgRecvV3Response(frame[1:])
	if err != nil {
		t.Fatal(err)
	}
	if room := MaxFrameSize - 11; !strings.HasPrefix(long, parsed.Text) || len(parsed.Text)+len("é") <= room {
		t.Errorf("text cut to %d bytes, want the longest whole-rune prefix that fits", len(parsed.Text))
	}
}

func TestResponseToBytesSNRClamps(t *testing.T) {
	if got := (PushLogRxDataResponse{LastSNR: 100}).ToBytes()[1]; got != 0x7f {
		t.Errorf("SNR 100 dB encoded as 0x%02x, want 0x7f", got)
	}
	if got := (PushLogRxDataResponse{LastSNR: -100}).ToBytes()[1]; got != 0x80 {
		t.Errorf("SNR -100 dB encoded as 0x%02x, want 0x80", got)
	}
}

func TestResponseToBytesDispatch(t *testing.T) {
	if _, err := (Response{Code: RespOk, Data: ErrResponse{}}).ToBytes(); err == nil {
		t.Error("a code that does not match its data encoded without error")
	}
	if _, err := (Response{Code: RespOk, Data: 42}).ToBytes(); err == nil {
		t.Error("an unencodable data type encoded without error")
	}
	raw, err := Response{Code: 0x7e, Data: []byte{1, 2}}.ToBytes()
	if err != nil || !bytes.Equal(raw, []byte{0x7e, 1, 2}) {
		t.Errorf("raw payload encoded as % x, %v; want 7e 01 02", raw, err)
	}
}
