package common

import (
	"context"
	"errors"
	"ktun/protocol"
	"net"
	"syscall"

	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"go.uber.org/zap"
)

var DefaultDialer *net.Dialer

func InitTUN(name string) (*water.Interface, error) {
	// 创建tun
	config := water.Config{
		DeviceType: water.TUN,
	}
	config.Name = name

	ifce, err := water.New(config)
	if err != nil {
		Logger.Warn("创建失败", zap.String("tunName", name), zap.Error(err))
		return nil, errors.New("创建失败")
	}
	return ifce, nil
}

func CreateTUN(name, addr string) (*water.Interface, error) {
	// 创建tun
	config := water.Config{
		DeviceType: water.TUN,
	}
	config.Name = name

	ifce, err := water.New(config)
	if err != nil {
		Logger.Warn("创建失败", zap.String("tunName", name), zap.String("ipCIDR", addr), zap.Error(err))
		return nil, errors.New("创建失败")
	}
	// 绑定IP
	err = bindIP(name, addr)
	if err != nil {
		DelTUN(name)
		return nil, err
	}
	// 启动tun
	err = upTUN(name)
	if err != nil {
		DelTUN(name)
		return nil, err
	}
	return ifce, nil
}

func bindIP(name, addr string) error {
	tun0, err := GetTunLink(name)
	if err != nil {
		return err
	}
	ipAddr, ipNet, err := net.ParseCIDR(addr)
	if err != nil {
		Logger.Warn("IP解析失败", zap.String("tunName", name), zap.String("ipCIDR", addr), zap.Error(err))
		return errors.New("IP解析失败")
	}
	ipNet.IP = ipAddr
	brAddr := &netlink.Addr{
		IPNet: ipNet,
	}
	err = netlink.AddrAdd(tun0, brAddr)
	if err != nil {
		Logger.Warn("IP绑定失败", zap.String("tunName", name), zap.String("ipCIDR", addr), zap.Error(err))
		return errors.New("IP绑定失败")
	}
	return nil
}

func GetTunLink(name string) (*netlink.Tuntap, error) {
	l, err := netlink.LinkByName(name)
	if err != nil {
		Logger.Warn("设备创建失败", zap.String("tunName", name), zap.Error(err))
		return nil, errors.New("设备创建失败")
	}
	tun0, ok := l.(*netlink.Tuntap)
	if !ok {
		Logger.Warn("设备已存在，创建失败", zap.String("tunName", name), zap.Error(err))
		return nil, errors.New("设备已存在，创建失败")
	}
	return tun0, nil
}

func upTUN(name string) error {
	tun0, err := GetTunLink(name)
	if err != nil {
		return err
	}
	err = netlink.LinkSetUp(tun0)
	if err != nil {
		Logger.Warn("设备启动失败", zap.String("tunName", name), zap.Error(err))
		return errors.New("设备启动失败")
	}
	return nil
}

func DelTUN(name string) error {
	tun0, err := GetTunLink(name)
	if err != nil {
		return nil
	}
	err = netlink.LinkDel(tun0)
	if err != nil {
		Logger.Warn("设备删除失败", zap.String("tunName", name), zap.Error(err))
	}
	return err
}

func ReadPack(ctx context.Context, tunIface *water.Interface) <-chan *protocol.KTunMessage {
	tun0, _ := GetTunLink(tunIface.Name())
	buffer := make([]byte, tun0.MTU)
	packs := make(chan *protocol.KTunMessage, 1)
	go func() {
		for {
			select {
			case <-ctx.Done():
				close(packs)
				return
			default:
				n, err := tunIface.Read(buffer)
				if err != nil {
					Logger.Error("设备读取错误", zap.Error(err))
					close(packs)
					return
				}
				if !IsIPv4Packet(buffer) {
					break
				}
				msg := protocol.NewKTunMessage().WithNetPack().FullBody(buffer[:n])
				err = msg.Parse()
				if err != nil {
					Logger.Error("包解析失败, 丢弃", zap.Error(err))
					break
				}
				select {
				case <-ctx.Done():
					return
				case packs <- msg:
				}
			}
		}
	}()
	return packs
}

func GetDefaultDev(nh *netlink.Handle) (link netlink.Link) {
	if nh == nil {
		nh, _ = netlink.NewHandle()
	}
	rs, err := nh.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		Logger.Error("路由查询失败", zap.Error(err))
	}
	for _, r := range rs {
		if r.Dst == nil {
			link, err = netlink.LinkByIndex(r.LinkIndex)
			if err != nil {
				Logger.Error("设备查询失败", zap.Error(err))
			}
			break
		}
	}
	return
}

func GetDefaultRoute(nh *netlink.Handle, link netlink.Link) (route netlink.Route) {
	if nh == nil {
		nh, _ = netlink.NewHandle()
	}
	rs, err := nh.RouteList(link, netlink.FAMILY_V4)
	if err != nil {
		Logger.Error("路由查询失败", zap.Error(err))
	}
	for _, r := range rs {
		if r.Dst == nil {
			route = r
			break
		}
	}
	return
}

func GetDefaultAddr(nh *netlink.Handle, link netlink.Link) (addr netlink.Addr) {
	if nh == nil {
		nh, _ = netlink.NewHandle()
	}

	addrs, err := nh.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		Logger.Error("地址查询失败", zap.Error(err))
	}
	if len(addrs) > 0 {
		addr = addrs[0]
	}
	return
}

func GetDial(ns, dev string) *net.Dialer {
	nh, _ := netns.GetFromName(ns)
	netns.Set(nh)
	DefaultDialer = &net.Dialer{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				// Set the network namespace of the socket
				err := syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, dev)
				if err != nil {
					Logger.Warn("命名空间切换失败", zap.String("dev", dev), zap.Error(err))
				}
			})
		},
	}
	return DefaultDialer
}
