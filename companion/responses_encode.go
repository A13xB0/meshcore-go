package companion

import (
	"encoding/binary"
	"fmt"
	"math"

	meshcore "github.com/meshcore-go/meshcore-go"
)

// ToBytes encodes a response or push whose Data is one of this package's types, or the raw payload of an unknown code.
func (r Response) ToBytes() ([]byte, error) {
	switch d := r.Data.(type) {
	case interface{ ToBytes() []byte }:
		b := d.ToBytes()
		if b[0] != r.Code {
			return nil, fmt.Errorf("response code 0x%02x does not match its data, which encodes as 0x%02x", r.Code, b[0])
		}
		return b, nil
	case []byte:
		return append([]byte{r.Code}, d...), nil
	}
	return nil, fmt.Errorf("response code 0x%02x: cannot encode %T", r.Code, r.Data)
}

func snrToWire(db float32) byte {
	q := math.Round(float64(db) * 4)
	return byte(int8(max(math.MinInt8, min(math.MaxInt8, q))))
}

func le16(b []byte, v uint16) []byte { return binary.LittleEndian.AppendUint16(b, v) }
func le32(b []byte, v uint32) []byte { return binary.LittleEndian.AppendUint32(b, v) }

// fixedString writes s as a NUL-padded field of n bytes, keeping room for the terminator.
func fixedString(b []byte, s string, n int) []byte {
	field := make([]byte, n)
	copy(field, meshcore.TruncateUTF8(s, n-1))
	return append(b, field...)
}

// msgText caps the text so the whole frame stays within MaxFrameSize, as the firmware does.
func msgText(b []byte, text string) []byte {
	return append(b, meshcore.TruncateUTF8(text, max(0, MaxFrameSize-len(b)))...)
}

func signedPrefix(b []byte, txtType byte, prefix []byte) []byte {
	if txtType != TxtTypeSignedPlain {
		return b
	}
	p := make([]byte, 4)
	copy(p, prefix)
	return append(b, p...)
}

func contactRecord(code byte, key [32]byte, typ, flags, outPathLen byte, outPath [64]byte, name string, lastAdvert uint32, lat, lon int32, lastMod uint32) []byte {
	b := make([]byte, 0, 148)
	b = append(b, code)
	b = append(b, key[:]...)
	b = append(b, typ, flags, outPathLen)
	b = append(b, outPath[:]...)
	b = fixedString(b, name, 32)
	b = le32(b, lastAdvert)
	b = le32(b, uint32(lat))
	b = le32(b, uint32(lon))
	return le32(b, lastMod)
}

func (r OkResponse) ToBytes() []byte {
	if !r.HasValue {
		return []byte{RespOk}
	}
	return le32([]byte{RespOk}, r.Value)
}

func (r ErrResponse) ToBytes() []byte {
	if !r.HasErrorCode {
		return []byte{RespErr}
	}
	return []byte{RespErr, r.ErrorCode}
}

func (r ContactsStartResponse) ToBytes() []byte {
	if !r.HasCount {
		return []byte{RespContactsStart}
	}
	return le32([]byte{RespContactsStart}, r.Count)
}

func (r ContactResponse) ToBytes() []byte {
	return contactRecord(RespContact, r.PublicKey, r.Type, r.Flags, r.OutPathLen, r.OutPath, r.AdvertName, r.LastAdvert, r.AdvertLatitude, r.AdvertLongitude, r.LastModified)
}

func (r EndOfContactsResponse) ToBytes() []byte {
	return le32([]byte{RespEndOfContacts}, r.MostRecentLastmod)
}

func (r SelfInfoResponse) ToBytes() []byte {
	b := []byte{RespSelfInfo, r.AdvertType, r.TxPower, r.MaxTxPower}
	b = append(b, r.PublicKey[:]...)
	b = le32(b, uint32(r.AdvertLatitude))
	b = le32(b, uint32(r.AdvertLongitude))
	b = append(b, r.Reserved[:]...)
	b = append(b, r.ManualAddContacts)
	b = le32(b, r.RadioFrequency)
	b = le32(b, r.RadioBandwidth)
	b = append(b, r.RadioSpreadFactor, r.RadioCodingRate)
	return append(b, r.Name...)
}

func (r DeviceInfoResponse) ToBytes() []byte {
	b := []byte{RespDeviceInfo, r.FirmwareVersion}
	if r.FirmwareVersion < 3 {
		return b
	}
	b = append(b, byte(min(r.MaxContacts/2, 255)), r.MaxChannels)
	b = le32(b, r.BLEPin)
	b = fixedString(b, r.FirmwareBuildDate, 12)
	b = fixedString(b, r.Model, 40)
	b = fixedString(b, r.FirmwareVersionStr, 20)
	repeat := byte(0)
	if r.RepeatEnabled {
		repeat = 1
	}
	return append(b, repeat, r.PathHashMode)
}

func (r BattAndStorageResponse) ToBytes() []byte {
	b := le16([]byte{RespBattAndStorage}, r.BatteryMilliVolts)
	b = le32(b, r.UsedStorageKB)
	return le32(b, r.TotalStorageKB)
}

func (r SentResponse) ToBytes() []byte {
	switch {
	case r.HasExtended:
		flood := byte(0)
		if r.IsFlood {
			flood = 1
		}
		b := le32([]byte{RespSent, flood}, r.Tag)
		return le32(b, r.EstTimeout)
	case r.HasAckCode:
		return le32([]byte{RespSent}, r.AckCode)
	}
	return []byte{RespSent}
}

func (r CustomVarsResponse) ToBytes() []byte {
	return append([]byte{RespCustomVars}, r.Vars...)
}

func (r AdvertPathResponse) ToBytes() []byte {
	b := le32([]byte{RespAdvertPath}, r.RecvTimestamp)
	return append(append(b, r.PathLen), r.Path...)
}

func (r StatsResponse) ToBytes() []byte {
	b := []byte{RespStats, r.StatsType}
	switch {
	case r.Core != nil:
		b = le16(b, r.Core.BatteryMV)
		b = le32(b, r.Core.UptimeSecs)
		b = le16(b, r.Core.ErrFlags)
		b = append(b, r.Core.QueueLen)
	case r.Radio != nil:
		b = le16(b, uint16(r.Radio.NoiseFloor))
		b = append(b, byte(r.Radio.LastRSSI), snrToWire(r.Radio.LastSNR))
		b = le32(b, r.Radio.TxAirSecs)
		b = le32(b, r.Radio.RxAirSecs)
	case r.Packets != nil:
		for _, v := range []uint32{r.Packets.PacketsRecv, r.Packets.PacketsSent, r.Packets.SentFlood, r.Packets.SentDirect, r.Packets.RecvFlood, r.Packets.RecvDirect, r.Packets.RecvErrors} {
			b = le32(b, v)
		}
	}
	return b
}

func (r AutoAddConfigResponse) ToBytes() []byte {
	return []byte{RespAutoAddConfig, r.Config, r.MaxHops}
}

func (r AllowedRepeatFreqResponse) ToBytes() []byte {
	b := []byte{RespAllowedRepeatFreq}
	for _, fr := range r.Ranges {
		b = le32(b, fr.LowerFreq)
		b = le32(b, fr.UpperFreq)
	}
	return b
}

func (r CurrTimeResponse) ToBytes() []byte {
	return le32([]byte{RespCurrTime}, r.Timestamp)
}

func (NoMoreMessagesResponse) ToBytes() []byte {
	return []byte{RespNoMoreMessages}
}

func (r ContactMsgRecvResponse) ToBytes() []byte {
	b := append([]byte{RespContactMsgRecv}, r.PubKeyPrefix[:]...)
	b = le32(append(b, r.PathLen, r.TxtType), r.SenderTimestamp)
	return msgText(signedPrefix(b, r.TxtType, r.SenderPrefix), r.Text)
}

func (r ChannelMsgRecvResponse) ToBytes() []byte {
	b := le32([]byte{RespChannelMsgRecv, r.ChannelIdx, r.PathLen, r.TxtType}, r.SenderTimestamp)
	return msgText(signedPrefix(b, r.TxtType, r.SenderPrefix), r.Text)
}

func (r ContactMsgRecvV3Response) ToBytes() []byte {
	b := append([]byte{RespContactMsgRecvV3, snrToWire(r.SNR), 0, 0}, r.PubKeyPrefix[:]...)
	b = le32(append(b, r.PathLen, r.TxtType), r.SenderTimestamp)
	return msgText(signedPrefix(b, r.TxtType, r.SenderPrefix), r.Text)
}

func (r ChannelMsgRecvV3Response) ToBytes() []byte {
	b := le32([]byte{RespChannelMsgRecvV3, snrToWire(r.SNR), 0, 0, r.ChannelIdx, r.PathLen, r.TxtType}, r.SenderTimestamp)
	return msgText(signedPrefix(b, r.TxtType, r.SenderPrefix), r.Text)
}

func (r ChannelInfoResponse) ToBytes() []byte {
	b := fixedString([]byte{RespChannelInfo, r.ChannelIdx}, r.Name, 32)
	return append(b, r.Secret[:]...)
}

func (r ExportContactResponse) ToBytes() []byte {
	return append([]byte{RespExportContact}, r.AdvertData...)
}

func (r PrivateKeyResponse) ToBytes() []byte {
	return append([]byte{RespPrivateKey}, r.PrivateKey[:]...)
}

func (DisabledResponse) ToBytes() []byte {
	return []byte{RespDisabled}
}

func (r SignStartResponse) ToBytes() []byte {
	return le32([]byte{RespSignStart, 0}, r.MaxSignDataLen)
}

func (r SignatureResponse) ToBytes() []byte {
	return append([]byte{RespSignature}, r.Signature[:]...)
}

func (r ChannelDataRecvResponse) ToBytes() []byte {
	b := []byte{RespChannelDataRecv, snrToWire(r.SNR), 0, 0, byte(r.ChannelIdx), r.PathLen}
	b = le16(b, r.DataType)
	return append(append(b, byte(len(r.Data))), r.Data...)
}

func (r TuningParamsResponse) ToBytes() []byte {
	return le32(le32([]byte{RespTuningParams}, milli(r.RxDelayBase)), milli(r.AirtimeFactor))
}

func (r DefaultFloodScopeResponse) ToBytes() []byte {
	if r.Name == "" {
		return []byte{RespDefaultFloodScope}
	}
	b := fixedString([]byte{RespDefaultFloodScope}, r.Name, 31)
	key := make([]byte, 16)
	copy(key, r.Key)
	return append(b, key...)
}

func (r PushAdvertResponse) ToBytes() []byte {
	return append([]byte{PushAdvert}, r.PublicKey[:]...)
}

func (r PushPathUpdatedResponse) ToBytes() []byte {
	return append([]byte{PushPathUpdated}, r.PublicKey[:]...)
}

func (r PushSendConfirmedResponse) ToBytes() []byte {
	return le32(le32([]byte{PushSendConfirmed}, r.AckCode), r.RoundTrip)
}

func (PushMsgWaitingResponse) ToBytes() []byte {
	return []byte{PushMsgWaiting}
}

func (r PushRawDataResponse) ToBytes() []byte {
	return append([]byte{PushRawData, snrToWire(r.LastSNR), byte(r.LastRSSI), 0xff}, r.Payload...)
}

func (r PushLoginSuccessResponse) ToBytes() []byte {
	b := append([]byte{PushLoginSuccess, r.Permissions}, r.PubKeyPrefix[:]...)
	if !r.HasServerInfo {
		return b
	}
	return append(le32(b, r.ServerTime), r.ACL, r.FirmwareLevel)
}

func (r PushLoginFailResponse) ToBytes() []byte {
	return append([]byte{PushLoginFail, 0}, r.PubKeyPrefix[:]...)
}

func (r PushStatusResp) ToBytes() []byte {
	b := append([]byte{PushStatusResponse, 0}, r.PubKeyPrefix[:]...)
	return append(b, r.StatusData...)
}

func (r PushLogRxDataResponse) ToBytes() []byte {
	return append([]byte{PushLogRxData, snrToWire(r.LastSNR), byte(r.LastRSSI)}, r.Raw...)
}

func (r PushTraceDataResponse) ToBytes() []byte {
	b := le32([]byte{PushTraceData, 0, r.PathLen, r.Flags}, r.Tag)
	b = le32(b, r.AuthCode)
	b = append(append(b, r.PathHashes...), r.PathSnrs...)
	return append(b, snrToWire(r.LastSNR))
}

func (r PushNewAdvertResponse) ToBytes() []byte {
	return contactRecord(PushNewAdvert, r.PublicKey, r.Type, r.Flags, r.OutPathLen, r.OutPath, r.AdvertName, r.LastAdvert, r.AdvertLatitude, r.AdvertLongitude, r.LastModified)
}

func (r PushTelemetryResp) ToBytes() []byte {
	b := append([]byte{PushTelemetryResponse, 0}, r.PubKeyPrefix[:]...)
	return append(b, r.LPPData...)
}

func (r PushBinaryResp) ToBytes() []byte {
	return append(le32([]byte{PushBinaryResponse, 0}, r.Tag), r.ResponseData...)
}

func (r PushPathDiscoveryResp) ToBytes() []byte {
	b := append([]byte{PushPathDiscoveryResponse, 0}, r.PubKeyPrefix[:]...)
	b = append(append(b, r.OutPathLen), r.OutPath...)
	return append(append(b, r.InPathLen), r.InPath...)
}

func (r PushControlDataResp) ToBytes() []byte {
	return append([]byte{PushControlData, snrToWire(r.SNR), byte(r.RSSI), r.PathLen}, r.Payload...)
}

func (r PushContactDeletedResponse) ToBytes() []byte {
	return append([]byte{PushContactDeleted}, r.PublicKey[:]...)
}

func (PushContactsFullResponse) ToBytes() []byte {
	return []byte{PushContactsFull}
}
