package meshcore

import "fmt"

type GroupData struct {
	ChannelHash      byte
	MAC              [2]byte
	EncryptedPayload []byte
}

func GroupDataFromBytes(data []byte) (*GroupData, error) {
	if len(data) < 3 {
		return nil, fmt.Errorf("%w: group data needs 3 header bytes, have %d", ErrTooShort, len(data))
	}
	return &GroupData{
		ChannelHash:      data[0],
		MAC:              [2]byte{data[1], data[2]},
		EncryptedPayload: data[3:],
	}, nil
}

// MaxGroupDataLen is the firmware's MAX_GROUP_DATA_LENGTH.
const MaxGroupDataLen = MaxPacketPayload - cipherBlockSize - 3

// NewGroupData encrypts data_type, length and data for a channel, the plaintext layout the firmware sends.
func NewGroupData(channelHash byte, psk []byte, dataType uint16, data []byte) (*GroupData, error) {
	if len(data) > MaxGroupDataLen {
		return nil, fmt.Errorf("group data is %d bytes, max %d", len(data), MaxGroupDataLen)
	}
	plaintext := append([]byte{byte(dataType), byte(dataType >> 8), byte(len(data))}, data...)
	encrypted, err := EncryptThenMAC(psk, plaintext)
	if err != nil {
		return nil, err
	}
	return &GroupData{
		ChannelHash:      channelHash,
		MAC:              [2]byte{encrypted[0], encrypted[1]},
		EncryptedPayload: encrypted[cipherMACSize:],
	}, nil
}

func (g *GroupData) ToBytes() ([]byte, error) {
	return append([]byte{g.ChannelHash, g.MAC[0], g.MAC[1]}, g.EncryptedPayload...), nil
}

func (g *GroupData) VerifyMAC(channelKey []byte) bool {
	return g.Decrypt(channelKey) != nil
}

// Decrypt returns the plaintext, or nil if the MAC does not verify.
func (g *GroupData) Decrypt(channelKey []byte) []byte {
	return macDecrypt(channelKey, g.MAC, g.EncryptedPayload)
}
