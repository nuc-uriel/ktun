package client

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"time"

	"ktun/common"
	"ktun/protocol"

	"github.com/coreos/go-iptables/iptables"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"go.uber.org/zap"
)

var (
	TunName string = "ktun0"
	NsName  string = "kns0"
)

type client struct {
	Addr          string
	IpCIDR        string
	Ctx           context.Context
	Cancel        context.CancelFunc
	sendTunQueue  chan []byte
	sendConQueue  chan []byte
	sendKTunQueue chan []byte
	heartbeat     *time.Timer
	ipRange       [][]uint32
	defaltRange   [][]uint32
}

func (c *client) connect(dev string) *net.TCPConn {
	nh, _ := netns.GetFromName(NsName)
	netns.Set(nh)
	conn, err := common.GetDial(NsName, dev).Dial("tcp", c.Addr)
	if err != nil {
		common.Logger.Fatal("连接服务器失败", zap.String("addr", c.Addr), zap.Error(err))
	}
	return conn.(*net.TCPConn)
}

func (c *client) sendServer(tunIface *water.Interface, ipAddr net.IP, nTun *water.Interface) {
	packs := common.ReadPack(c.Ctx, tunIface)
	for msg := range packs {
		common.Logger.Debug("TUN", zap.String("Src", msg.IPHeader.Src.String()), zap.String("Dst", msg.IPHeader.Dst.String()), zap.Any("Data", msg.Data))
		if !msg.IPHeader.Src.Equal(ipAddr) {
			continue
		}
		if c.ipRange == nil || len(c.ipRange) == 0 || common.IsInternal(c.ipRange, msg.IPHeader.Dst.String()) {
			c.sendMsg(msg.Data, c.sendKTunQueue)
			common.Logger.Debug("本机转发请求", zap.String("Src", msg.IPHeader.Src.String()), zap.String("Dst", msg.IPHeader.Dst.String()))
		} else {
			c.sendMsg(msg.Encode(), c.sendConQueue)
			common.Logger.Debug("👄本机发出请求👄", zap.String("Src", msg.IPHeader.Src.String()), zap.String("Dst", msg.IPHeader.Dst.String()))
		}
	}
}

func (c *client) sendMsg(data []byte, queue chan []byte) {
	select {
	case <-c.Ctx.Done():
	case queue <- data:
	case <-time.After(time.Second * 30):
		common.Logger.Warn("包转发超时，已丢弃")
	}
}

func (c *client) sender(writer io.Writer, queue chan []byte) {
	for {
		select {
		case <-c.Ctx.Done():
			return
		case pack, isOpen := <-queue:
			if !isOpen {
				return
			}
			writer.Write(pack)
		}
	}
}

func (c *client) reveiveTun(nTun *water.Interface, ipAddr net.IP) {
	packs := common.ReadPack(c.Ctx, nTun)
	for msg := range packs {
		common.Logger.Debug("NTUN", zap.String("Src", msg.IPHeader.Src.String()), zap.String("Dst", msg.IPHeader.Dst.String()), zap.Any("Data", msg.Data))
		if msg.IPHeader.Dst.Equal(ipAddr) {
			c.sendMsg(msg.Data, c.sendTunQueue)
		}
	}
}

func (c *client) resetPong() {
	c.heartbeat.Reset(time.Minute)
}

func (c *client) startPing(conn *net.TCPConn) {
	c.heartbeat = time.NewTimer(time.Minute)
	ticker := time.NewTicker(time.Second * 20)
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
			c.sendMsg(protocol.BuildHBPing().Encode(), c.sendConQueue)
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

func (c *client) connSub(dev string) (*net.TCPConn, error) {
	code := []byte(strings.Split(c.IpCIDR, "/")[0])
	conn := c.connect(dev)
	reqMsg := protocol.NewKTunMessage().WithReq().WithSub().FullBody(code)
	_, err := conn.Write(reqMsg.Encode())
	if err != nil {
		conn.Close()
		return nil, err
	}
	timeout := time.NewTimer(time.Minute)

	for {
		select {
		case <-c.Ctx.Done():
			timeout.Stop()
			conn.Close()
			return nil, errors.New("退出")
		case <-timeout.C:
			conn.Close()
			return nil, errors.New("服务器超时, 断开连接")
		default:
			msg, err := protocol.Decode(conn)
			if err != nil {
				conn.Close()
				common.Logger.Info("😭服务器断开连接😭。。。", zap.Error(err))
				return nil, err
			}
			if msg.TypeCheck(protocol.Sub) && common.Bytes2Str(msg.Data) == common.Bytes2Str(code) {
				return conn, nil
			}
		}
	}
}

func (c *client) reveiveServer(conn *net.TCPConn, ipAddr net.IP) {
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
				c.sendMsg(msg.Data, c.sendTunQueue)
			}
		}
	}
}

func (c *client) updateIpRange() {
	ticker := time.NewTicker(time.Hour * 24)
	for {
		select {
		case <-c.Ctx.Done():
			ticker.Stop()
			return
		case <-ticker.C:
			c.initIPRange()
		}
	}
}

func (c *client) initIPRange() (err error) {
	maxTime := 3
	nextTime := 3
	common.Logger.Info("IP池生成中...")
	// url := "http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest"
	url := "http://203.119.102.40/apnic/stats/apnic/delegated-apnic-latest"
	for i := 0; i <= maxTime; i++ {
		c.ipRange, err = common.InternalIPInit(url, c.defaltRange)
		if err != nil {
			common.Logger.Warn("国内IP池生成失败,等待重试", zap.Error(err))
		}
		if err == nil || i == maxTime {
			break
		}
		time.Sleep(time.Second * time.Duration(nextTime))
		nextTime *= 2
	}
	if err == nil {
		common.Logger.Info("IP池生成完成", zap.Int("长度", len(c.ipRange)))
	}
	return
}

func (c *client) Run(subCount int) {
	// 创建tun0
	mainTunI, err := common.InitTUN(TunName)
	if err != nil {
		common.Logger.Error("主空间TUN设备创建失败", zap.Error(err))
		return
	}

	// 获取主命名空间句柄
	mainNs, _ := netns.Get()
	mainNh, _ := netlink.NewHandleAt(mainNs)

	// 备份主命名空间路由和地址
	dev := common.GetDefaultDev(mainNh)
	devName := dev.Attrs().Name
	if dev == nil {
		common.Logger.Error("获取默认网络设备失败", zap.Error(err))
	}

	devRoute := common.GetDefaultRoute(mainNh, dev)
	devAddr := common.GetDefaultAddr(mainNh, dev)

	// 创建新命名空间句柄
	ktNs, err := netns.NewNamed(NsName)
	if err != nil {
		common.Logger.Error("创建命名空间失败", zap.Error(err))
	}
	defer ktNs.Close()

	ktNh, err := netlink.NewHandleAt(ktNs)
	if err != nil {
		common.Logger.Error("创建命名空间句柄失败", zap.Error(err))
	}
	defer ktNh.Close()

	// 开启回环口
	lo, _ := ktNh.LinkByName("lo")
	ktNh.LinkSetUp(lo)

	// 将主空间默认设备移入新空间
	mainNh.LinkSetNsFd(dev, int(ktNs))
	nDev, err := ktNh.LinkByName(devName)
	if err != nil {
		common.Logger.Error("获取默认网络设备失败", zap.Error(err))
	}

	// 绑定地址
	ktNh.AddrAdd(nDev, &devAddr)

	// 启动设备
	err = ktNh.LinkSetUp(nDev)
	if err != nil {
		common.Logger.Error("网络启动失败", zap.Error(err))
	}

	// 添加默认路由
	err = ktNh.RouteAdd(&devRoute)
	if err != nil {
		common.Logger.Error("路由创建失败", zap.Error(err))
	}

	ktTunI, err := common.InitTUN(TunName)
	if err != nil {
		common.Logger.Error("网络空间TUN设备创建失败", zap.Error(err))
		return
	}

	defer func() {
		ktNh.LinkSetNsFd(nDev, int(mainNs))
		dev, err = mainNh.LinkByName(devName)
		if err != nil {
			common.Logger.Error("获取默认设备失败", zap.Error(err))
		}
		mainNh.AddrAdd(dev, &devAddr)
		err = mainNh.LinkSetUp(dev)
		if err != nil {
			common.Logger.Error("网络启动失败", zap.Error(err))
		}
		err = mainNh.RouteAdd(&devRoute)
		if err != nil {
			common.Logger.Error("路由创建失败", zap.Error(err))
		}
		netns.DeleteNamed(NsName)
	}()

	// 连接服务器
	conn := c.connect(devName)
	// 关闭连接
	defer func() {
		conn.Close()
	}()

	common.Logger.Info("🎉服务器连接成功🎉", zap.String("addr", c.Addr))

	devIpAddr, devIpNet, _ := net.ParseCIDR(devAddr.IPNet.String())
	devIpNet.IP = devIpAddr
	privS, privE, _ := common.PrivateIPv4Range(devIpNet)
	c.defaltRange = [][]uint32{{privS, privE}}

	// 初始化国内IP解析
	err = c.initIPRange()
	if err != nil {
		common.Logger.Error("国内IP池初始化失败", zap.Error(err))
		return
	}

	// 启动定时刷新机制
	go c.updateIpRange()

	// dhcp协商IP
	if err := c.dhcp(conn); err != nil {
		common.Logger.Fatal("DHCP获取失败", zap.Error(err))
	}

	// 扩展子链接
	subs := make([]*net.TCPConn, 0)
	for i := 0; i < subCount; i++ {
		sub, err := c.connSub(devName)
		if err != nil {
			common.Logger.Warn("扩展通道失败", zap.Error(err))
		} else {
			subs = append(subs, sub)
		}
	}

	ipAddr, ipNet, _ := net.ParseCIDR(c.IpCIDR)
	ipNet.IP = ipAddr
	// 命名空间内需设置与主不同的ip地址
	tun0IP := common.IPv42Unit32(ipAddr)
	start, end, _ := common.PrivateIPv4Range(ipNet)
	for i := start + 1; i < end; i++ {
		if tun0IP != i {
			ipNet.IP = common.Unit322IPv4(i)
			break
		}
	}

	tun1, _ := ktNh.LinkByName(TunName)
	ktNh.AddrAdd(tun1, &netlink.Addr{
		IPNet: ipNet,
	})
	ktNh.LinkSetUp(tun1)

	netns.Set(ktNs)
	// 配置masquerade
	// iptables -t nat -A POSTROUTING -s 172.22.0.0/16 -j MASQUERADE
	ipt, err := iptables.New()
	if err != nil {
		common.Logger.Warn("IPTable配置失败", zap.Error(err))
	}
	if exist, err := ipt.Exists("nat", "POSTROUTING", "-s", c.IpCIDR, "-j", "MASQUERADE"); err != nil {
		common.Logger.Warn("IPTable配置查询失败", zap.Error(err))
	} else if !exist {
		err = ipt.Append("nat", "POSTROUTING", "-s", c.IpCIDR, "-j", "MASQUERADE")
		if err != nil {
			common.Logger.Error("IPTable配置添加失败", zap.Error(err))
			return
		}
	}

	// 主命名空间添加tun设备
	tun0, err := mainNh.LinkByName(TunName)
	if err != nil {
		common.Logger.Error("设备查询失败", zap.Error(err))
		return
	}

	defer mainNh.LinkDel(tun0)

	// 重新设置主命名空间地址
	ipAddr, ipNet, _ = net.ParseCIDR(c.IpCIDR)
	ipNet.IP = ipAddr

	mainNh.AddrAdd(tun0, &netlink.Addr{
		IPNet: ipNet,
	})
	mainNh.LinkSetUp(tun0)
	// 主命名空间添加默认路由
	mainNh.RouteAdd(&netlink.Route{
		Gw:  ipAddr,
		Dst: nil,
	})

	// 监听tun
	go c.sendServer(mainTunI, ipAddr, ktTunI)
	go c.startPing(conn)
	go c.reveiveTun(ktTunI, ipAddr)

	go c.reveiveServer(conn, ipAddr)
	go c.sender(conn, c.sendConQueue)

	go c.sender(mainTunI, c.sendTunQueue)
	go c.sender(ktTunI, c.sendKTunQueue)

	for _, subConn := range subs {
		go c.reveiveServer(subConn, ipAddr)
		go c.sender(subConn, c.sendConQueue)
	}

	<-c.Ctx.Done()
}

func New(ctx context.Context, cancel context.CancelFunc, addr string) *client {
	return &client{
		Addr:          addr,
		Ctx:           ctx,
		Cancel:        cancel,
		sendTunQueue:  make(chan []byte, 200),
		sendConQueue:  make(chan []byte, 200),
		sendKTunQueue: make(chan []byte, 200),
		defaltRange:   make([][]uint32, 0),
	}
}
