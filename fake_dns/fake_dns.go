package fakedns

import (
	"context"
	"errors"
	"ktun/common"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
	"go.uber.org/zap"
)

var fd *FakeDns

type FakeDns struct {
	FakeIpCIDR string
	DefaultDns string
	Ctx        context.Context
	ipRange    [][]uint32
	ipPool     []string
	fakeMap    map[string]string
	realMap    map[string]string
	lock       *sync.Mutex
}

func (fd *FakeDns) GetRealIP(fakeIP string) net.IP {
	if ip, exist := fd.fakeMap[fakeIP]; exist {
		return net.ParseIP(ip)
	}
	return nil
}

func (fd *FakeDns) GetFakeIP(ip string) net.IP {
	if fakeIP, exist := fd.realMap[ip]; exist {
		return net.ParseIP(fakeIP)
	}
	return nil
}

func (fd *FakeDns) acquireIP() (string, error) {
	fd.lock.Lock()
	defer fd.lock.Unlock()
	if len(fd.ipPool) == 0 {
		return "", errors.New("连接已满")
	}
	ip := fd.ipPool[0]
	fd.ipPool = fd.ipPool[1:]
	return ip, nil
}

func (fd *FakeDns) RelaseIP(ip string) {
	fd.lock.Lock()
	defer fd.lock.Unlock()
	fd.ipPool = append(fd.ipPool, ip)
}

func (fd *FakeDns) handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	common.Logger.Debug("Received DNS request", zap.Any("Body", r))
	msg := new(dns.Msg)
	msg.SetReply(r)

	for _, question := range r.Question {
		domain := question.Name
		defaultResp, err := dns.Exchange(r, fd.DefaultDns)
		if err != nil {
			common.Logger.Warn("DNS 请求错误", zap.String("Domain", domain), zap.Error(err))
			continue
		}
		if question.Qtype == dns.TypeA {
			ip := ""
			for _, ans := range defaultResp.Answer {
				ip = ans.(*dns.A).A.String()
				if common.IsInternal(fd.ipRange, ip) {
					msg.Answer = append(msg.Answer, ans)
				}
			}
			if ip != "" && len(msg.Answer) == 0 {
				fakeIP, err := fd.acquireIP()
				if err != nil {
					common.Logger.Warn("Fake IP 分配失败, 返回真实IP", zap.String("Domain", domain), zap.Error(err))
					msg.Answer = defaultResp.Answer
				}
				fd.fakeMap[fakeIP] = ip
				fd.realMap[ip] = fakeIP
				fIP := net.ParseIP(fakeIP)
				if fIP == nil {
					common.Logger.Warn("Failed to parse IP address", zap.Any("IP", fIP))
					continue
				}
				rr := &dns.A{
					Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   fIP,
				}
				msg.Answer = append(msg.Answer, rr)
			}
		} else {
			msg.Answer = defaultResp.Answer
			if len(msg.Answer) == 0 {
				msg.Answer = msg.Answer[:0]
				switch question.Qtype {
				case dns.TypeA:
					ip := net.ParseIP("10.0.0.1")
					if ip == nil {
						common.Logger.Warn("Failed to parse IP address", zap.Any("IP", ip))
						continue
					}
					rr := &dns.A{
						Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
						A:   ip,
					}
					msg.Answer = append(msg.Answer, rr)

				case dns.TypeAAAA:
					ip := net.ParseIP("2001:db8::1")
					if ip == nil {
						common.Logger.Warn("Failed to parse IP address", zap.Any("IP", ip))
						continue
					}
					rr := &dns.AAAA{
						Hdr:  dns.RR_Header{Name: domain, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
						AAAA: ip,
					}
					msg.Answer = append(msg.Answer, rr)
				default:
					common.Logger.Warn("Ignoring DNS request for unsupported record type", zap.Any("Qtypte", question.Qtype))
				}
			}
		}
	}
	w.WriteMsg(msg)
}

func (fd *FakeDns) updateIpRange() {
	ticker := time.NewTicker(time.Hour * 24)
	for {
		select {
		case <-fd.Ctx.Done():
			ticker.Stop()
			return
		case <-ticker.C:
			fd.initIPRange()
		}
	}
}

func (fd *FakeDns) initIPRange() error {
	common.Logger.Info("IP池生成中...")
	// url := "http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest"
	url := "http://203.119.102.40/apnic/stats/apnic/delegated-apnic-latest"
	ipRange, err := common.InternalIPInit(url, [][]uint32{})
	if err != nil {
		common.Logger.Error("国内IP池生成失败", zap.Error(err))
		return err
	}
	fd.ipRange = ipRange
	common.Logger.Info("IP池生成完成")
	return nil
}

func (fd *FakeDns) initIpPool() {
	ipAddr, ipNet, _ := net.ParseCIDR(fd.FakeIpCIDR)
	ipNet.IP = ipAddr
	start, end, err := common.PrivateIPv4Range(ipNet)
	if err != nil {
		common.Logger.Error("IP池解析失败", zap.Error(err))
	}
	for i := start + 1; i < end; i++ {
		fd.ipPool = append(fd.ipPool, common.Unit322IPv4(i).String())
	}
}

func (fd *FakeDns) initDNSServer() {
	server := &dns.Server{
		Addr:    ":53",
		Net:     "udp",
		Handler: dns.HandlerFunc(fd.handleDNSRequest),
	}
	go func() {
		<-fd.Ctx.Done()
		server.Shutdown()
		common.Logger.Info("FakeDNS服务关闭成功")
	}()
	err := server.ListenAndServe()
	if err != nil {
		common.Logger.Error("FakeDNS服务启动失败", zap.Error(err))
		return
	}
}

func (fd *FakeDns) Run() (err error) {
	// 初始化国内IP解析
	err = fd.initIPRange()
	if err != nil {
		common.Logger.Error("国内IP池初始化失败", zap.Error(err))
		return
	}
	// 初始化IP池
	fd.initIpPool()

	// 启动定时刷新机制
	go fd.initIpPool()

	// 启动DNS服务器
	go fd.initDNSServer()
	common.Logger.Info("FakeDNS服务启动成功")
	return
}

func New(ctx context.Context, fakeIpCIDR, defaultDns string) *FakeDns {
	if fd == nil {
		fd = &FakeDns{
			FakeIpCIDR: fakeIpCIDR,
			DefaultDns: defaultDns,
			Ctx:        ctx,
			ipPool:     make([]string, 0),
			fakeMap:    make(map[string]string, 0),
			realMap:    make(map[string]string, 0),
			lock:       new(sync.Mutex),
		}
	}
	return fd
}
