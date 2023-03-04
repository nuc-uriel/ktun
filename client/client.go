package client

import (
	"context"
	"errors"
	"log"
	"net"
	"time"

	"ktun/common"
	"ktun/protocol"

	"github.com/songgao/water"
	"go.uber.org/zap"
)

type client struct {
	Addr      string
	TunName   string
	IpCIDR    string
	Ctx       context.Context
	Cancel    context.CancelFunc
	msgQueue  chan *protocol.KTunMessage
	heartbeat *time.Timer
}

func (c *client) connect() *net.TCPConn {
	servAddr, err := net.ResolveTCPAddr("tcp", c.Addr)
	if err != nil {
		common.Logger.Fatal("服务器IP解析失败", zap.String("addr", c.Addr), zap.Error(err))
	}
	conn, err := net.DialTCP("tcp", nil, servAddr)
	if err != nil {
		common.Logger.Fatal("连接服务器失败", zap.String("addr", c.Addr), zap.Error(err))
	}
	return conn
}

func (c *client) sendServer(tunIface *water.Interface, conn *net.TCPConn, ipAddr net.IP) {
	packs := common.ReadPack(c.Ctx, tunIface)
	for msg := range packs {
		if msg.IPHeader.Src.Equal(ipAddr) {
			conn.Write(msg.Encode())
			common.Logger.Debug("👄本机发出请求👄", zap.String("Src", msg.IPHeader.Src.String()), zap.String("Dst", msg.IPHeader.Dst.String()))
		}
	}
}

func (c *client) resetPong() {
	c.heartbeat.Reset(time.Minute)
}

func (c *client) startPing(conn *net.TCPConn) {
	c.heartbeat = time.NewTimer(time.Minute)
	ticker := time.NewTicker(time.Second * 30)
	for {
		select {
		case <-c.Ctx.Done():
			ticker.Stop()
			c.heartbeat.Stop()
			return
		case <-c.heartbeat.C:
			common.Logger.Info("服务器超时, 断开连接。。。")
			c.Cancel()
		case <-ticker.C:
			conn.Write(protocol.BuildHBPing().Encode())
			c.heartbeat.Reset(time.Second * 20)
			common.Logger.Debug("💓PING💓")
		}
	}
}

func (c *client) dhcp(conn *net.TCPConn) error {
	// TODO 此处可添加鉴权
	reqMsg := protocol.NewKTunMessage().WithReq().WithDHCP().FullBody([]byte("HI"))
	_, err := conn.Write(reqMsg.Encode())
	if err != nil {
		return err
	}
	timeout := time.NewTimer(time.Minute)

	for {
		select {
		case <-c.Ctx.Done():
			timeout.Stop()
			return errors.New("退出")
		case <-timeout.C:
			common.Logger.Info("服务器超时, 断开连接。。。")
			return errors.New("服务器超时, 断开连接")
		default:
			msg, err := protocol.Decode(conn)
			if err != nil {
				common.Logger.Info("😭服务器断开连接😭。。。", zap.Error(err))
				return err
			}
			if msg.TypeCheck(protocol.DHCP) {
				c.IpCIDR = string(msg.Data)
				return nil
			}
		}
	}
}

func (c *client) reveiveServer(tunIface *water.Interface, conn *net.TCPConn, ipAddr net.IP) {
	for {
		select {
		case <-c.Ctx.Done():
			return
		default:
			msg, err := protocol.Decode(conn)
			if err != nil {
				common.Logger.Info("😭服务器断开连接😭。。。", zap.Error(err))
				c.Cancel()
				break
			}
			c.resetPong()
			if msg.TypeCheck(protocol.Heartbeat) {
			} else if msg.IPHeader.Dst.Equal(ipAddr) {
				tunIface.Write(msg.Data)
				common.Logger.Debug("👂🏻本机收到数据👂🏻", zap.String("Src", msg.IPHeader.Src.String()), zap.String("Dst", msg.IPHeader.Dst.String()))
			}
		}
	}
}

func (c *client) Run() {
	// 连接服务器
	conn := c.connect()
	// 关闭连接
	defer func() {
		conn.Close()
	}()

	common.Logger.Info("🎉服务器连接成功🎉", zap.String("addr", c.Addr))

	// dhcp协商IP
	if err := c.dhcp(conn); err != nil {
		log.Fatalln(err)
	}

	// 创建tun
	tunIface, err := common.CreateTUN(c.TunName, c.IpCIDR)
	if err != nil {
		log.Fatalln(err)
	}

	common.Logger.Info("🎉TUN设备启动成功🎉", zap.String("tunName", c.TunName), zap.String("ipCIDR", c.IpCIDR))

	ipAddr, _, _ := net.ParseCIDR(c.IpCIDR)

	// 监听tun
	go c.sendServer(tunIface, conn, ipAddr)
	go c.startPing(conn)
	go c.reveiveServer(tunIface, conn, ipAddr)

	<-c.Ctx.Done()
}

func New(ctx context.Context, cancel context.CancelFunc, addr, tunName string) *client {
	return &client{
		Addr:     addr,
		TunName:  tunName,
		Ctx:      ctx,
		Cancel:   cancel,
		msgQueue: make(chan *protocol.KTunMessage, 1),
	}
}
