package protocol

import (
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/net/ipv4"
)

type KTunMessage struct {
	MsgType  MsgType
	Data     []byte
	IPHeader *ipv4.Header
}

type MsgType uint8

const (
	Auth      MsgType = 1 << iota // 鉴权
	DHCP                          // dhcp分配IP
	Heartbeat                     // 心跳
	NetPack                       // 网络包
	Other1                        // 占位
	Other2                        // 占位
	OK                            // 确认 | 0-> ERR
	Rrequest                      // 请求 / 0-> 响应
)

const (
	HeaderSize  = 5
	MaxBodySize = 65535 - HeaderSize
)

// Encode encodes a message to a byte slice
func (msg *KTunMessage) Encode() []byte {
	buf := make([]byte, HeaderSize+len(msg.Data))
	buf[0] = byte(msg.MsgType)
	binary.BigEndian.PutUint32(buf[1:5], uint32(len(msg.Data)))
	copy(buf[HeaderSize:], msg.Data)
	return buf
}

// Decode decodes a message from an io.Reader
func Decode(r io.Reader) (*KTunMessage, error) {
	header := make([]byte, HeaderSize)
	_, err := io.ReadFull(r, header)
	if err != nil {
		return nil, err
	}
	msgType := MsgType(header[0])
	bodySize := int(binary.BigEndian.Uint32(header[1:5]))
	if bodySize > MaxBodySize {
		return nil, errors.New("消息体过大")
	}
	body := make([]byte, bodySize)
	_, err = io.ReadFull(r, body)
	if err != nil {
		return nil, err
	}
	var ipHeader *ipv4.Header
	if msgType&NetPack == NetPack {
		ipHeader, err = ipv4.ParseHeader(body)
		if err != nil {
			return nil, errors.New("网络包解析失败")
		}
	}
	return &KTunMessage{MsgType: msgType, IPHeader: ipHeader, Data: body}, nil
}

func (msg *KTunMessage) Parse() error {
	if msg.MsgType == NetPack {
		header, err := ipv4.ParseHeader(msg.Data)
		if err != nil {
			return errors.New("网络包解析失败")
		}
		msg.IPHeader = header
	}
	return nil
}

func BuildHBPing() *KTunMessage {
	return NewKTunMessage().WithReq().WithHeartbeat().FullBody([]byte("PING"))
}

func BuildHBPong() *KTunMessage {
	return NewKTunMessage().WithResp().WithHeartbeat().FullBody([]byte("PONG"))
}

func (msg *KTunMessage) BuildOK() {
	msg.WithOK().Data = []byte("OK")
}

func (msg *KTunMessage) BuildErr(err string) {
	msg.WithErr().Data = []byte(err)
}

func NewKTunMessage() *KTunMessage {
	return new(KTunMessage)
}

func (msg *KTunMessage) WithAuth() *KTunMessage {
	msg.MsgType |= Auth
	return msg
}

func (msg *KTunMessage) WithDHCP() *KTunMessage {
	msg.MsgType |= DHCP
	return msg
}

func (msg *KTunMessage) WithHeartbeat() *KTunMessage {
	msg.MsgType |= Heartbeat
	return msg
}

func (msg *KTunMessage) WithNetPack() *KTunMessage {
	msg.MsgType |= NetPack
	return msg
}

func (msg *KTunMessage) WithOK() *KTunMessage {
	msg.MsgType |= OK
	return msg
}

func (msg *KTunMessage) WithErr() *KTunMessage {
	msg.MsgType &= ^OK
	return msg
}

func (msg *KTunMessage) WithReq() *KTunMessage {
	msg.MsgType |= Rrequest
	return msg
}

func (msg *KTunMessage) WithResp() *KTunMessage {
	msg.MsgType &= ^Rrequest
	return msg
}

func (msg *KTunMessage) FullBody(data []byte) *KTunMessage {
	msg.Data = data
	return msg
}

func (msg *KTunMessage) TypeCheck(expect MsgType) bool {
	return msg.MsgType&expect == expect
}
