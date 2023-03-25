package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"ktun/common"
	"ktun/protocol"
	"net"
	"sync"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/songgao/water"
	"go.uber.org/zap"
)

type server struct {
	Addr        string
	TunName     string
	IpCIDR      string
	Ctx         context.Context
	Cancel      context.CancelFunc
	clientConns map[string]chan []byte
	ipPool      []string
	msgQueue    chan []byte
	lock        *sync.Mutex
	mask        int
}

func (s *server) startTunner() *net.TCPListener {
	servAddr, err := net.ResolveTCPAddr("tcp", ":7890")
	if err != nil {
		common.Logger.Fatal("服务器IP解析失败", zap.String("addr", s.Addr), zap.Error(err))
	}
	servConn, err := net.ListenTCP("tcp", servAddr)
	if err != nil {
		common.Logger.Fatal("服务端启动失败", zap.String("addr", s.Addr), zap.Error(err))
	}
	return servConn
}

func (s *server) accept(servConn *net.TCPListener) {
	for {
		select {
		case <-s.Ctx.Done():
			return
		default:
			conn, err := servConn.Accept()
			if err != nil {
				break
			}
			common.Logger.Info("👏🏻客户端接入👏🏻", zap.String("Client", conn.RemoteAddr().String()))
			logger := common.Logger.With(zap.String("Client", conn.RemoteAddr().String()))
			go s.handleClient(conn, logger)
		}

	}
}

func (s *server) acquireIP() (string, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if len(s.ipPool) == 0 {
		return "", errors.New("连接已满")
	}
	ip := s.ipPool[0]
	s.ipPool = s.ipPool[1:]
	return ip, nil
}

func (s *server) relaseIP(ip string) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.ipPool = append(s.ipPool, ip)
}

func (s *server) handleClient(conn net.Conn, log *zap.Logger) {
	defer conn.Close()
	ip, err := s.acquireIP()
	if err != nil {
		log.Error("IP分配失败", zap.Error(err))
	}
	isSub := false
	defer func() {
		if !isSub {
			s.relaseIP(ip)
		}
		if queue, exist := s.clientConns[ip]; exist {
			close(queue)
		}
	}()
	alloced := false
	for {
		select {
		case <-s.Ctx.Done():
			return
		default:
			msg, err := protocol.Decode(conn)
			if err != nil {
				log.Info("😭客户端断开连接😭。。。", zap.Error(err))
				delete(s.clientConns, ip)
				return
			}
			if msg.TypeCheck(protocol.Heartbeat | protocol.Rrequest) {
				conn.Write(protocol.BuildHBPong().Encode())
				log.Debug("💓PONG💓")
			} else if msg.TypeCheck(protocol.DHCP | protocol.Rrequest) {
				ipCIDR := fmt.Sprintf("%s/%d", ip, s.mask)
				dhcpMsg := protocol.NewKTunMessage().WithResp().WithDHCP().FullBody([]byte(ipCIDR))
				conn.Write(dhcpMsg.Encode())
				log = log.With(zap.String("TUN IP", ip))
				log.Debug("IP分配成功")
				s.clientConns[ip] = make(chan []byte, 200)
				go s.sender(conn, s.clientConns[ip])
				alloced = true
			} else if msg.TypeCheck(protocol.Sub | protocol.Rrequest) {
				subIp := string(msg.Data)
				log = log.With(zap.String("TUN IP", subIp))
				if queue, exist := s.clientConns[subIp]; exist {
					subMsg := protocol.NewKTunMessage().WithResp().WithSub().FullBody([]byte(subIp))
					conn.Write(subMsg.Encode())
					go s.sender(conn, queue)
					log.Debug("附属通道建立成功")
					s.relaseIP(ip)
					ip = subIp
					alloced = true
					isSub = true
				} else {
					return
				}
			} else if msg.TypeCheck(protocol.NetPack|protocol.Rrequest) && !alloced {
				log.Warn("IP未分配, 包丢弃")
			} else {
				s.sendMsg(msg.Data, s.msgQueue)
			}
		}
	}
}

func (s *server) reciver(tunIface *water.Interface) {
	packs := common.ReadPack(s.Ctx, tunIface)
	for msg := range packs {
		if queue, ok := s.clientConns[msg.IPHeader.Dst.String()]; ok {
			s.sendMsg(msg.Encode(), queue)
			common.Logger.Debug("👄本机发出数据👄", zap.String("Src", msg.IPHeader.Src.String()), zap.String("Dst", msg.IPHeader.Dst.String()))
		}
	}
}

func (s *server) initIpPool() {
	ipAddr, ipNet, _ := net.ParseCIDR(s.IpCIDR)
	ipNet.IP = ipAddr
	start, end, err := common.PrivateIPv4Range(ipNet)
	if err != nil {
		common.Logger.Error("IP池解析失败", zap.Error(err))
	}
	s.mask, _ = ipNet.Mask.Size()
	sIP := ipAddr.String()
	if common.IPv42Unit32(ipAddr) == start {
		sIP = common.Unit322IPv4(start + 1).String()
	}
	for i := start + 1; i < end; i++ {
		ip := common.Unit322IPv4(i).String()
		if ip != sIP {
			s.ipPool = append(s.ipPool, ip)
		}
	}
	s.IpCIDR = fmt.Sprintf("%s/%d", sIP, s.mask)
}

func (s *server) sendMsg(data []byte, queue chan []byte) {
	select {
	case <-s.Ctx.Done():
	case queue <- data:
	case <-time.After(time.Second * 30):
		common.Logger.Warn("包转发超时，已丢弃")
	}
}

func (s *server) sender(writer io.Writer, queue chan []byte) {
	for {
		select {
		case <-s.Ctx.Done():
			return
		case pack, isOpen := <-queue:
			if !isOpen {
				return
			}
			writer.Write(pack)
		}
	}
}

func (s *server) Run() {
	// 解析IP池
	s.initIpPool()

	// 创建tun
	tunIface, err := common.CreateTUN(s.TunName, s.IpCIDR)
	if err != nil {
		common.Logger.Error("TUN启动失败", zap.String("tunName", s.TunName), zap.String("ipCIDR", s.IpCIDR), zap.Error(err))
		return
	}

	// 配置masquerade
	// iptables -t nat -A POSTROUTING -s 10.0.10.0/24 -o enp0s3 -j MASQUERADE
	// iptables -t nat -A POSTROUTING -s 172.22.0.0/16 -j MASQUERADE
	ipt, err := iptables.New()
	if err != nil {
		common.Logger.Warn("IPTable配置失败", zap.Error(err))
	}
	if exist, err := ipt.Exists("nat", "POSTROUTING", "-s", s.IpCIDR, "-j", "MASQUERADE"); err != nil {
		common.Logger.Warn("IPTable配置查询失败", zap.Error(err))
	} else if !exist {
		err = ipt.Append("nat", "POSTROUTING", "-s", s.IpCIDR, "-j", "MASQUERADE")
		if err != nil {
			common.Logger.Error("IPTable配置添加失败", zap.Error(err))
			return
		}
	}

	// 删除masquerade
	defer func() {
		err = ipt.Delete("nat", "POSTROUTING", "-s", s.IpCIDR, "-o", "-j", "MASQUERADE")
		if err != nil {
			common.Logger.Warn("IPTable删除失败", zap.Error(err))
		}
	}()

	common.Logger.Info("🎉TUN设备启动成功🎉", zap.String("tunName", s.TunName), zap.String("ipCIDR", s.IpCIDR))

	// 启动服务器
	servConn := s.startTunner()

	common.Logger.Info("🎉服务器启动成功🎉", zap.String("addr", s.Addr))

	// 关闭服务器
	defer func() {
		servConn.Close()
	}()

	// 监听服务器端
	go s.accept(servConn)

	// 监听tun
	go s.reciver(tunIface)
	go s.sender(tunIface, s.msgQueue)

	<-s.Ctx.Done()
}

func New(ctx context.Context, cancel context.CancelFunc, addr, tunName, ipCIDR string) *server {
	return &server{
		Addr:        addr,
		TunName:     tunName,
		IpCIDR:      ipCIDR,
		Ctx:         ctx,
		Cancel:      cancel,
		clientConns: make(map[string]chan []byte),
		ipPool:      make([]string, 0),
		msgQueue:    make(chan []byte, 200),
		lock:        new(sync.Mutex),
	}
}
