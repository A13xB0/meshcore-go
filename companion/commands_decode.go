package companion

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

	meshcore "github.com/meshcore-go/meshcore-go"
)

// Command is one app-to-device command; ToBytes re-encodes it.
type Command interface {
	ToBytes() []byte
}

// CommandError is a frame the firmware refuses; ErrCode is the ERR_CODE_* it answers with.
type CommandError struct {
	Cmd     byte
	ErrCode byte
	Reason  string
}

func (e *CommandError) Error() string {
	return fmt.Sprintf("command 0x%02x: %s", e.Cmd, e.Reason)
}

func unsupported(cmd byte, format string, args ...any) error {
	return &CommandError{Cmd: cmd, ErrCode: ErrCodeUnsupportedCmd, Reason: fmt.Sprintf(format, args...)}
}

func illegalArg(cmd byte, format string, args ...any) error {
	return &CommandError{Cmd: cmd, ErrCode: ErrCodeIllegalArg, Reason: fmt.Sprintf(format, args...)}
}

func notFound(cmd byte, format string, args ...any) error {
	return &CommandError{Cmd: cmd, ErrCode: ErrCodeNotFound, Reason: fmt.Sprintf(format, args...)}
}

func tooShort(f []byte, need int) error {
	return unsupported(f[0], "frame too short: got %d bytes, need at least %d", len(f), need)
}

var commandParsers = map[byte]func([]byte) (Command, error){
	CmdAppStart:             cmdParser(parseAppStart),
	CmdSendTxtMsg:           cmdParser(parseSendTxtMsg),
	CmdSendChannelTxtMsg:    cmdParser(parseSendChannelTxtMsg),
	CmdGetContacts:          cmdParser(parseGetContacts),
	CmdGetDeviceTime:        bare(GetDeviceTimeCommand{}),
	CmdSetDeviceTime:        cmdParser(parseSetDeviceTime),
	CmdSendSelfAdvert:       cmdParser(parseSendSelfAdvert),
	CmdSetAdvertName:        cmdParser(parseSetAdvertName),
	CmdAddUpdateContact:     cmdParser(parseAddUpdateContact),
	CmdSyncNextMessage:      bare(SyncNextMessageCommand{}),
	CmdSetRadioParams:       cmdParser(parseSetRadioParams),
	CmdSetRadioTxPower:      cmdParser(parseSetTxPower),
	CmdResetPath:            cmdParser(parseResetPath),
	CmdSetAdvertLatLon:      cmdParser(parseSetAdvertLatLon),
	CmdRemoveContact:        cmdParser(parseRemoveContact),
	CmdShareContact:         cmdParser(parseShareContact),
	CmdExportContact:        cmdParser(parseExportContact),
	CmdImportContact:        cmdParser(parseImportContact),
	CmdReboot:               cmdParser(parseReboot),
	CmdGetBattAndStorage:    bare(GetBattAndStorageCommand{}),
	CmdSetTuningParams:      cmdParser(parseSetTuningParams),
	CmdDeviceQuery:          cmdParser(parseDeviceQuery),
	CmdExportPrivateKey:     bare(ExportPrivateKeyCommand{}),
	CmdImportPrivateKey:     cmdParser(parseImportPrivateKey),
	CmdSendRawData:          cmdParser(parseSendRawData),
	CmdSendLogin:            cmdParser(parseSendLogin),
	CmdSendStatusReq:        cmdParser(parseSendStatusReq),
	CmdHasConnection:        cmdParser(parseHasConnection),
	CmdLogout:               cmdParser(parseLogout),
	CmdGetContactByKey:      cmdParser(parseGetContactByKey),
	CmdGetChannel:           cmdParser(parseGetChannel),
	CmdSetChannel:           cmdParser(parseSetChannel),
	CmdSignStart:            bare(SignStartCommand{}),
	CmdSignData:             cmdParser(parseSignData),
	CmdSignFinish:           bare(SignFinishCommand{}),
	CmdSendTracePath:        cmdParser(parseSendTracePath),
	CmdSetDevicePin:         cmdParser(parseSetDevicePin),
	CmdSetOtherParams:       cmdParser(parseSetOtherParams),
	CmdSendTelemetryReq:     cmdParser(parseSendTelemetryReq),
	CmdGetCustomVars:        bare(GetCustomVarsCommand{}),
	CmdSetCustomVar:         cmdParser(parseSetCustomVar),
	CmdGetAdvertPath:        cmdParser(parseGetAdvertPath),
	CmdGetTuningParams:      bare(GetTuningParamsCommand{}),
	CmdSendBinaryReq:        cmdParser(parseSendBinaryReq),
	CmdFactoryReset:         cmdParser(parseFactoryReset),
	CmdSendPathDiscoveryReq: cmdParser(parseSendPathDiscoveryReq),
	CmdSetFloodScopeKey:     cmdParser(parseSetFloodScope),
	CmdSendControlData:      cmdParser(parseSendControlData),
	CmdGetStats:             cmdParser(parseGetStats),
	CmdSendAnonReq:          cmdParser(parseSendAnonReq),
	CmdSetAutoAddConfig:     cmdParser(parseSetAutoAddConfig),
	CmdGetAutoAddConfig:     bare(GetAutoAddConfigCommand{}),
	CmdGetAllowedRepeatFreq: bare(GetAllowedRepeatFreqCommand{}),
	CmdSetPathHashMode:      cmdParser(parseSetPathHashMode),
	CmdSendChannelData:      cmdParser(parseSendChannelData),
	CmdSetDefaultFloodScope: cmdParser(parseSetDefaultFloodScope),
	CmdGetDefaultFloodScope: bare(GetDefaultFloodScopeCommand{}),
	CmdSendRawPacket:        cmdParser(parseSendRawPacket),
}

func cmdParser[T Command](f func([]byte) (T, error)) func([]byte) (Command, error) {
	return func(b []byte) (Command, error) {
		c, err := f(b)
		if err != nil {
			return nil, err
		}
		return c, nil
	}
}

func bare(c Command) func([]byte) (Command, error) {
	return func([]byte) (Command, error) { return c, nil }
}

// ParseCommand decodes one frame from an app, code byte first, accepting what the firmware accepts.
func ParseCommand(frame []byte) (Command, error) {
	if len(frame) == 0 {
		return nil, fmt.Errorf("frame data cannot be empty")
	}
	p, ok := commandParsers[frame[0]]
	if !ok {
		return nil, unsupported(frame[0], "unknown command")
	}
	return p(frame)
}

func clone(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return bytes.Clone(b)
}

func key32(b []byte) (k [32]byte) {
	copy(k[:], b)
	return k
}

func u32(b []byte) uint32 { return binary.LittleEndian.Uint32(b) }

func parseAppStart(f []byte) (AppStartCommand, error) {
	if len(f) < 8 {
		return AppStartCommand{}, tooShort(f, 8)
	}
	return AppStartCommand{AppVersion: f[1], AppName: readCString(f[8:])}, nil
}

func parseSendTxtMsg(f []byte) (SendTxtMsgCommand, error) {
	if len(f) < 14 {
		return SendTxtMsgCommand{}, tooShort(f, 14)
	}
	c := SendTxtMsgCommand{TxtType: f[1], Attempt: f[2], SenderTimestamp: u32(f[3:7]), Text: readCString(f[13:])}
	copy(c.PubKeyPrefix[:], f[7:13])
	return c, nil
}

func parseSendChannelTxtMsg(f []byte) (SendChannelTxtMsgCommand, error) {
	if len(f) < 7 {
		return SendChannelTxtMsgCommand{}, tooShort(f, 7)
	}
	return SendChannelTxtMsgCommand{TxtType: f[1], ChannelIdx: f[2], SenderTimestamp: u32(f[3:7]), Text: string(f[7:])}, nil
}

func parseGetContacts(f []byte) (GetContactsCommand, error) {
	if len(f) < 5 {
		return GetContactsCommand{}, nil
	}
	return GetContactsCommand{Since: u32(f[1:5]), HasSince: true}, nil
}

func parseSetDeviceTime(f []byte) (SetDeviceTimeCommand, error) {
	if len(f) < 5 {
		return SetDeviceTimeCommand{}, tooShort(f, 5)
	}
	return SetDeviceTimeCommand{EpochSecs: u32(f[1:5])}, nil
}

func parseSendSelfAdvert(f []byte) (SendSelfAdvertCommand, error) {
	return SendSelfAdvertCommand{Flood: len(f) >= 2 && f[1] == 1}, nil
}

func parseSetAdvertName(f []byte) (SetAdvertNameCommand, error) {
	if len(f) < 2 {
		return SetAdvertNameCommand{}, tooShort(f, 2)
	}
	return SetAdvertNameCommand{Name: readCString(f[1:])}, nil
}

func parseAddUpdateContact(f []byte) (AddUpdateContactCommand, error) {
	if len(f) < 36 {
		return AddUpdateContactCommand{}, tooShort(f, 36)
	}
	// The firmware reads the fixed part whatever the length; missing bytes read as zero here.
	full := make([]byte, 148)
	copy(full, f)
	c := AddUpdateContactCommand{
		PublicKey:        key32(full[1:33]),
		Type:             full[33],
		Flags:            full[34],
		OutPathLen:       full[35],
		Name:             meshcore.TruncateUTF8(readCString(full[100:132]), 31),
		LastAdvert:       u32(full[132:136]),
		Latitude:         int32(u32(full[136:140])),
		Longitude:        int32(u32(full[140:144])),
		LastModified:     u32(full[144:148]),
		OmitLocation:     len(f) < 144,
		OmitLastModified: len(f) < 148,
	}
	if c.OutPathLen != OutPathUnknown && meshcore.IsValidPathLen(c.OutPathLen) {
		c.OutPath = clone(full[36 : 36+pathByteLen(c.OutPathLen)])
	}
	if c.OmitLocation {
		c.Latitude, c.Longitude, c.LastModified, c.OmitLastModified = 0, 0, 0, false
	}
	return c, nil
}

func parseSetRadioParams(f []byte) (SetRadioParamsCommand, error) {
	if len(f) < 11 {
		return SetRadioParamsCommand{}, tooShort(f, 11)
	}
	return SetRadioParamsCommand{
		Frequency:    u32(f[1:5]),
		Bandwidth:    u32(f[5:9]),
		SpreadFactor: f[9],
		CodingRate:   f[10],
		ClientRepeat: len(f) > 11 && f[11] != 0,
	}, nil
}

func parseSetTxPower(f []byte) (SetTxPowerCommand, error) {
	if len(f) < 2 {
		return SetTxPowerCommand{}, tooShort(f, 2)
	}
	return SetTxPowerCommand{TxPower: f[1]}, nil
}

func parseResetPath(f []byte) (ResetPathCommand, error) {
	if len(f) < 33 {
		return ResetPathCommand{}, tooShort(f, 33)
	}
	return ResetPathCommand{PublicKey: key32(f[1:33])}, nil
}

func parseSetAdvertLatLon(f []byte) (SetAdvertLatLonCommand, error) {
	if len(f) < 9 {
		return SetAdvertLatLonCommand{}, tooShort(f, 9)
	}
	c := SetAdvertLatLonCommand{Latitude: int32(u32(f[1:5])), Longitude: int32(u32(f[5:9]))}
	if len(f) >= 13 {
		c.Altitude, c.HasAltitude = int32(u32(f[9:13])), true
	}
	return c, nil
}

// pubKeyCmd covers the commands the firmware runs with no length check, matching all 32 key bytes.
func pubKeyCmd(f []byte) ([32]byte, error) {
	if len(f) < 33 {
		return [32]byte{}, notFound(f[0], "public key shorter than 32 bytes")
	}
	return key32(f[1:33]), nil
}

func parseRemoveContact(f []byte) (RemoveContactCommand, error) {
	k, err := pubKeyCmd(f)
	return RemoveContactCommand{PublicKey: k}, err
}

func parseShareContact(f []byte) (ShareContactCommand, error) {
	k, err := pubKeyCmd(f)
	return ShareContactCommand{PublicKey: k}, err
}

func parseGetContactByKey(f []byte) (GetContactByKeyCommand, error) {
	k, err := pubKeyCmd(f)
	return GetContactByKeyCommand{PublicKey: k}, err
}

func parseExportContact(f []byte) (ExportContactCommand, error) {
	if len(f) < 33 {
		return ExportContactCommand{Self: true}, nil
	}
	return ExportContactCommand{PublicKey: key32(f[1:33])}, nil
}

func parseImportContact(f []byte) (ImportContactCommand, error) {
	if len(f) <= 2+32+64 {
		return ImportContactCommand{}, tooShort(f, 2+32+64+1)
	}
	return ImportContactCommand{AdvertData: clone(f[1:])}, nil
}

func parseReboot(f []byte) (RebootCommand, error) {
	if len(f) < 7 || string(f[1:7]) != "reboot" {
		return RebootCommand{}, unsupported(f[0], `reboot needs the literal "reboot"`)
	}
	return RebootCommand{}, nil
}

func parseSetTuningParams(f []byte) (SetTuningParamsCommand, error) {
	if len(f) < 9 {
		return SetTuningParamsCommand{}, tooShort(f, 9)
	}
	return SetTuningParamsCommand{
		RxDelayBase:   float32(float64(u32(f[1:5])) / 1000),
		AirtimeFactor: float32(float64(u32(f[5:9])) / 1000),
	}, nil
}

func parseDeviceQuery(f []byte) (DeviceQueryCommand, error) {
	if len(f) < 2 {
		return DeviceQueryCommand{}, tooShort(f, 2)
	}
	return DeviceQueryCommand{AppTargetVersion: f[1]}, nil
}

func parseImportPrivateKey(f []byte) (ImportPrivateKeyCommand, error) {
	if len(f) < 65 {
		return ImportPrivateKeyCommand{}, tooShort(f, 65)
	}
	var c ImportPrivateKeyCommand
	copy(c.PrivateKey[:], f[1:65])
	return c, nil
}

func parseSendRawData(f []byte) (SendRawDataCommand, error) {
	if len(f) < 6 {
		return SendRawDataCommand{}, tooShort(f, 6)
	}
	pathLen := int(int8(f[1]))
	if pathLen < 0 || 2+pathLen+4 > len(f) {
		return SendRawDataCommand{}, unsupported(f[0], "flood raw data, or a payload under 4 bytes")
	}
	return SendRawDataCommand{Path: clone(f[2 : 2+pathLen]), RawData: clone(f[2+pathLen:])}, nil
}

func parseSendLogin(f []byte) (SendLoginCommand, error) {
	if len(f) < 33 {
		return SendLoginCommand{}, tooShort(f, 33)
	}
	return SendLoginCommand{PublicKey: key32(f[1:33]), Password: readCString(f[33:])}, nil
}

func parseSendStatusReq(f []byte) (SendStatusReqCommand, error) {
	if len(f) < 33 {
		return SendStatusReqCommand{}, tooShort(f, 33)
	}
	return SendStatusReqCommand{PublicKey: key32(f[1:33])}, nil
}

func parseHasConnection(f []byte) (HasConnectionCommand, error) {
	if len(f) < 33 {
		return HasConnectionCommand{}, tooShort(f, 33)
	}
	return HasConnectionCommand{PublicKey: key32(f[1:33])}, nil
}

func parseLogout(f []byte) (LogoutCommand, error) {
	if len(f) < 33 {
		return LogoutCommand{}, tooShort(f, 33)
	}
	return LogoutCommand{PublicKey: key32(f[1:33])}, nil
}

func parseGetChannel(f []byte) (GetChannelCommand, error) {
	if len(f) < 2 {
		return GetChannelCommand{}, tooShort(f, 2)
	}
	return GetChannelCommand{ChannelIdx: f[1]}, nil
}

func parseSetChannel(f []byte) (SetChannelCommand, error) {
	if len(f) >= 2+32+32 {
		return SetChannelCommand{}, unsupported(f[0], "256-bit channel secrets are not supported")
	}
	if len(f) < 2+32+16 {
		return SetChannelCommand{}, tooShort(f, 2+32+16)
	}
	c := SetChannelCommand{ChannelIdx: f[1], Name: meshcore.TruncateUTF8(readCString(f[2:34]), 31)}
	copy(c.Secret[:], f[34:50])
	return c, nil
}

func parseSignData(f []byte) (SignDataCommand, error) {
	if len(f) < 2 {
		return SignDataCommand{}, tooShort(f, 2)
	}
	return SignDataCommand{Data: clone(f[1:])}, nil
}

func parseSendTracePath(f []byte) (SendTracePathCommand, error) {
	if len(f) <= 10 || len(f)-10 >= meshcore.MaxPacketPayload-5 {
		return SendTracePathCommand{}, unsupported(f[0], "trace path length %d out of range", len(f)-10)
	}
	flags := f[9]
	pathLen := len(f) - 10
	hashSize := 1 << (flags & 0x03)
	if pathLen/hashSize > meshcore.MaxPathSize || pathLen%hashSize != 0 {
		return SendTracePathCommand{}, illegalArg(f[0], "trace path of %d bytes is not a whole number of %d-byte hashes", pathLen, hashSize)
	}
	return SendTracePathCommand{Tag: u32(f[1:5]), Auth: u32(f[5:9]), Flags: flags, Path: clone(f[10:])}, nil
}

func parseSetDevicePin(f []byte) (SetDevicePinCommand, error) {
	if len(f) < 5 {
		return SetDevicePinCommand{}, tooShort(f, 5)
	}
	return SetDevicePinCommand{Pin: u32(f[1:5])}, nil
}

func parseSetOtherParams(f []byte) (SetOtherParamsCommand, error) {
	if len(f) < 2 {
		return SetOtherParamsCommand{}, tooShort(f, 2)
	}
	c := SetOtherParamsCommand{ManualAddContacts: f[1]}
	if len(f) >= 3 {
		c.HasTelemetryModes = true
		c.TelemetryModeBase = f[2] & 0x03
		c.TelemetryModeLocation = (f[2] >> 2) & 0x03
		c.TelemetryModeEnvironment = (f[2] >> 4) & 0x03
	}
	if len(f) >= 4 {
		c.HasAdvertLocPolicy, c.AdvertLocPolicy = true, f[3]
	}
	if len(f) >= 5 {
		c.HasMultiAcks, c.MultiAcks = true, f[4]
	}
	return c, nil
}

func parseSendTelemetryReq(f []byte) (SendTelemetryReqCommand, error) {
	switch {
	case len(f) >= 4+32:
		return SendTelemetryReqCommand{PublicKey: key32(f[4:36])}, nil
	case len(f) == 4:
		return SendTelemetryReqCommand{Self: true}, nil
	}
	return SendTelemetryReqCommand{}, unsupported(f[0], "frame of %d bytes is neither a self request (4) nor a contact request (36+)", len(f))
}

func parseSetCustomVar(f []byte) (SetCustomVarCommand, error) {
	if len(f) < 4 {
		return SetCustomVarCommand{}, tooShort(f, 4)
	}
	s := readCString(f[1:])
	name, value, ok := strings.Cut(s, ":")
	if !ok {
		return SetCustomVarCommand{}, illegalArg(f[0], "custom var has no ':' separator")
	}
	return SetCustomVarCommand{Name: name, Value: value}, nil
}

func parseGetAdvertPath(f []byte) (GetAdvertPathCommand, error) {
	if len(f) < 2+32 {
		return GetAdvertPathCommand{}, tooShort(f, 2+32)
	}
	return GetAdvertPathCommand{PublicKey: key32(f[2:34])}, nil
}

func parseSendBinaryReq(f []byte) (SendBinaryReqCommand, error) {
	if len(f) < 2+32 {
		return SendBinaryReqCommand{}, tooShort(f, 2+32)
	}
	return SendBinaryReqCommand{PublicKey: key32(f[1:33]), RequestData: clone(f[33:])}, nil
}

func parseFactoryReset(f []byte) (FactoryResetCommand, error) {
	if len(f) < 6 || string(f[1:6]) != "reset" {
		return FactoryResetCommand{}, unsupported(f[0], `factory reset needs the literal "reset"`)
	}
	return FactoryResetCommand{}, nil
}

func parseSendPathDiscoveryReq(f []byte) (SendPathDiscoveryReqCommand, error) {
	if len(f) < 2+32 || f[1] != 0 {
		return SendPathDiscoveryReqCommand{}, unsupported(f[0], "needs a zero reserved byte then a 32-byte key")
	}
	return SendPathDiscoveryReqCommand{PublicKey: key32(f[2:34])}, nil
}

func parseSetFloodScope(f []byte) (SetFloodScopeCommand, error) {
	if len(f) < 2 {
		return SetFloodScopeCommand{}, tooShort(f, 2)
	}
	switch f[1] {
	case 0:
		if len(f) >= 2+16 {
			return SetFloodScopeCommand{TransportKey: clone(f[2:18])}, nil
		}
		return SetFloodScopeCommand{}, nil
	case 1:
		return SetFloodScopeCommand{Unscoped: true}, nil
	}
	return SetFloodScopeCommand{}, unsupported(f[0], "unknown flood scope mode %d", f[1])
}

func parseSendControlData(f []byte) (SendControlDataCommand, error) {
	if len(f) < 2 || f[1]&0x80 == 0 {
		return SendControlDataCommand{}, unsupported(f[0], "control data must start with a byte that has the top bit set")
	}
	return SendControlDataCommand{ControlData: clone(f[1:])}, nil
}

func parseGetStats(f []byte) (GetStatsCommand, error) {
	if len(f) < 2 {
		return GetStatsCommand{}, tooShort(f, 2)
	}
	if f[1] > StatsTypePackets {
		return GetStatsCommand{}, illegalArg(f[0], "unknown stats type %d", f[1])
	}
	return GetStatsCommand{StatsType: f[1]}, nil
}

func parseSendAnonReq(f []byte) (SendAnonReqCommand, error) {
	if len(f) <= 1+32 {
		return SendAnonReqCommand{}, tooShort(f, 1+32+1)
	}
	return SendAnonReqCommand{PublicKey: key32(f[1:33]), RequestData: clone(f[33:])}, nil
}

func parseSetAutoAddConfig(f []byte) (SetAutoAddConfigCommand, error) {
	if len(f) < 2 {
		return SetAutoAddConfigCommand{}, tooShort(f, 2)
	}
	if len(f) < 3 {
		return SetAutoAddConfigCommand{Config: f[1], OmitMaxHops: true}, nil
	}
	return SetAutoAddConfigCommand{Config: f[1], MaxHops: f[2]}, nil
}

func parseSetPathHashMode(f []byte) (SetPathHashModeCommand, error) {
	if len(f) < 3 || f[1] != 0 {
		return SetPathHashModeCommand{}, unsupported(f[0], "needs a zero reserved byte then the mode")
	}
	if f[2] >= 3 {
		return SetPathHashModeCommand{}, illegalArg(f[0], "path hash mode %d out of range", f[2])
	}
	return SetPathHashModeCommand{Mode: f[2]}, nil
}

func parseSendChannelData(f []byte) (SendChannelDataCommand, error) {
	if len(f) < 4 {
		return SendChannelDataCommand{}, illegalArg(f[0], "frame too short: got %d bytes, need at least 4", len(f))
	}
	c := SendChannelDataCommand{ChannelIdx: f[1]}
	pathLen := f[2]
	i := 3
	if pathLen == OutPathUnknown {
		c.Flood = true
	} else {
		if !meshcore.IsValidPathLen(pathLen) {
			return SendChannelDataCommand{}, illegalArg(f[0], "invalid path length 0x%02x", pathLen)
		}
		n := pathByteLen(pathLen)
		if i+n > len(f) {
			return SendChannelDataCommand{}, illegalArg(f[0], "path runs past the end of the frame")
		}
		c.PathLen, c.Path = pathLen, clone(f[i:i+n])
		i += n
	}
	if i+2 > len(f) {
		return SendChannelDataCommand{}, illegalArg(f[0], "frame ends before the data type")
	}
	c.DataType = binary.LittleEndian.Uint16(f[i : i+2])
	c.Payload = clone(f[i+2:])
	return c, nil
}

func parseSetDefaultFloodScope(f []byte) (SetDefaultFloodScopeCommand, error) {
	if len(f) < 1+31+16 {
		return SetDefaultFloodScopeCommand{}, nil
	}
	return SetDefaultFloodScopeCommand{Name: meshcore.TruncateUTF8(readCString(f[1:32]), 30), Key: clone(f[32:48])}, nil
}

func parseSendRawPacket(f []byte) (SendRawPacketCommand, error) {
	if len(f) < 4 {
		return SendRawPacketCommand{}, tooShort(f, 4)
	}
	return SendRawPacketCommand{Priority: f[1], Packet: clone(f[2:])}, nil
}
