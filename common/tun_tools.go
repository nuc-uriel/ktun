package common

import (
	"context"
	"errors"
	"ktun/protocol"
	"net"

	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
)

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
	tun0, err := getTunLink(name)
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

func getTunLink(name string) (*netlink.Tuntap, error) {
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
	tun0, err := getTunLink(name)
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
	tun0, err := getTunLink(name)
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
	tun0, _ := getTunLink(tunIface.Name())
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
