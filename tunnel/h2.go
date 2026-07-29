package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	connectip "github.com/Diniboy1123/connect-ip-go"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/http2"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const (
	h2ConnectURI       = "https://cloudflareaccess.com"
	h2ServerName       = "consumer-masque.cloudflareclient.com"
	h2MTU              = 1280
	h2DialTimeout      = 10 * time.Second
	h2ConnectTimeout   = 15 * time.Second
	h2PingPeriod       = 30 * time.Second
	h2PingTimeout      = 10 * time.Second
	h2ReconnectDelay   = time.Second
	h2PacketHeadroom   = 1 // CONNECT-IP context ID 0 is a one-byte QUIC varint.
	h2PacketBufferSize = h2MTU + h2PacketHeadroom
)

var h2ConnectTemplate = uritemplate.MustNew(h2ConnectURI)

type h2Bundle struct {
	addr      string
	netConn   net.Conn
	client    *http2.ClientConn
	ipConn    *connectip.Conn
	cancel    context.CancelFunc
	failed    chan error
	failOnce  sync.Once
	closeOnce sync.Once
	done      chan struct{}
}

func (b *h2Bundle) fail(err error) {
	if err == nil {
		err = net.ErrClosed
	}
	b.failOnce.Do(func() {
		select {
		case b.failed <- err:
		default:
		}
	})
}

func (b *h2Bundle) close() {
	if b == nil {
		return
	}
	b.closeOnce.Do(func() {
		close(b.done)
		b.cancel()
		if b.ipConn != nil {
			_ = b.ipConn.Close()
		}
		if b.client != nil {
			_ = b.client.Close()
		}
		if b.netConn != nil {
			_ = b.netConn.Close()
		}
	})
}

// H2Client carries complete IP packets in HTTP/2 DATAGRAM capsules. A userspace
// netstack consumes those packets, so it needs neither root nor /dev/net/tun.
type H2Client struct {
	edgeAddrs []string
	tlsConfig *tls.Config
	addrIdx   int

	tunDev tun.Device
	tunNet *netstack.Net
	local4 net.IP
	local6 net.IP

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	connMu      sync.Mutex
	current     *h2Bundle
	connChanged chan struct{}
	closed      bool
	closeOnce   sync.Once
}

// NewH2Client establishes the first HTTP/2 CONNECT-IP tunnel and starts its
// reconnect supervisor.
func NewH2Client(edgeAddrs []string, tlsConfig *tls.Config, assignedIPv4, assignedIPv6 string) (*H2Client, error) {
	return NewH2ClientContext(context.Background(), edgeAddrs, tlsConfig, assignedIPv4, assignedIPv6)
}

// NewH2ClientContext uses setupCtx only to bound the initial connection. The
// established request is attached to the client's own lifetime context, so
// canceling setupCtx after this function returns does not tear down the tunnel.
func NewH2ClientContext(setupCtx context.Context, edgeAddrs []string, tlsConfig *tls.Config, assignedIPv4, assignedIPv6 string) (*H2Client, error) {
	if len(edgeAddrs) == 0 {
		return nil, errors.New("未提供任何 HTTP/2 边缘地址")
	}
	if tlsConfig == nil {
		return nil, errors.New("未提供 TLS 配置")
	}

	localAddresses := make([]netip.Addr, 0, 2)
	var local4, local6 net.IP
	for _, item := range []struct {
		value  string
		family int
	}{
		{assignedIPv4, 4},
		{assignedIPv6, 6},
	} {
		if strings.TrimSpace(item.value) == "" {
			continue
		}
		addr, err := parseAssignedAddress(item.value)
		if err != nil {
			return nil, fmt.Errorf("分配的 IPv%d 地址 %q 无效：%w", item.family, item.value, err)
		}
		if (item.family == 4) != addr.Is4() {
			return nil, fmt.Errorf("分配地址 %q 不是 IPv%d", item.value, item.family)
		}
		localAddresses = append(localAddresses, addr)
		if addr.Is4() {
			local4 = net.IP(append([]byte(nil), addr.AsSlice()...))
		} else {
			local6 = net.IP(append([]byte(nil), addr.AsSlice()...))
		}
	}
	if len(localAddresses) == 0 {
		return nil, errors.New("注册信息中没有可用于 CONNECT-IP 的分配地址")
	}

	dnsServers := []netip.Addr{
		netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("2606:4700:4700::1111"),
	}
	tunDev, tunNet, err := netstack.CreateNetTUN(localAddresses, dnsServers, h2MTU)
	if err != nil {
		return nil, fmt.Errorf("创建用户态网络栈失败：%w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	c := &H2Client{
		edgeAddrs:   append([]string(nil), edgeAddrs...),
		tlsConfig:   tlsConfig.Clone(),
		tunDev:      tunDev,
		tunNet:      tunNet,
		local4:      local4,
		local6:      local6,
		ctx:         ctx,
		cancel:      cancel,
		connChanged: make(chan struct{}),
	}

	bundle, err := c.dial(setupCtx)
	if err != nil {
		cancel()
		_ = tunDev.Close()
		return nil, err
	}
	if !c.setCurrent(bundle) {
		bundle.close()
		cancel()
		_ = tunDev.Close()
		return nil, net.ErrClosed
	}

	c.wg.Add(2)
	go func() {
		defer c.wg.Done()
		c.outboundPump()
	}()
	go func() {
		defer c.wg.Done()
		c.maintain(bundle)
	}()
	return c, nil
}

func parseAssignedAddress(value string) (netip.Addr, error) {
	value = strings.TrimSpace(value)
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix.Addr().Unmap(), nil
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, err
	}
	return addr.Unmap(), nil
}

func (c *H2Client) dial(ctx context.Context) (*h2Bundle, error) {
	var errs []string
	for i := 0; i < len(c.edgeAddrs); i++ {
		idx := (c.addrIdx + i) % len(c.edgeAddrs)
		addr := c.edgeAddrs[idx]
		bundle, err := c.dialAddr(ctx, addr)
		if err == nil {
			c.addrIdx = idx
			return bundle, nil
		}
		errs = append(errs, fmt.Sprintf("%s: %v", addr, err))
		if ctx.Err() != nil || c.ctx.Err() != nil {
			break
		}
		log.Printf("HTTP/2 边缘 %s 不可达（%v），尝试下一个地址 ...", addr, err)
	}
	return nil, fmt.Errorf("所有 HTTP/2 边缘地址均失败：%s", strings.Join(errs, "; "))
}

func (c *H2Client) dialAddr(setupCtx context.Context, edgeAddr string) (*h2Bundle, error) {
	log.Printf("TCP/TLS/HTTP2 拨号 %s（SNI=%s）...", edgeAddr, h2ServerName)

	dialCtx, cancelDial := context.WithTimeout(setupCtx, h2DialTimeout)
	defer cancelDial()
	netConn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", edgeAddr)
	if err != nil {
		return nil, fmt.Errorf("TCP 拨号失败：%w", err)
	}

	tlsConfig := c.tlsConfig.Clone()
	tlsConfig.ServerName = h2ServerName
	tlsConfig.NextProtos = []string{"h2"}
	tlsConn := tls.Client(netConn, tlsConfig)
	if err := tlsConn.HandshakeContext(dialCtx); err != nil {
		_ = netConn.Close()
		return nil, fmt.Errorf("TLS 握手失败：%w", err)
	}
	negotiated := tlsConn.ConnectionState().NegotiatedProtocol
	if negotiated == "" {
		negotiated = "none（显式发送 HTTP/2 preface）"
	}

	h2Transport := &http2.Transport{DisableCompression: true}
	clientConn, err := h2Transport.NewClientConn(tlsConn)
	if err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("初始化 HTTP/2 连接失败：%w", err)
	}

	lifeCtx, lifeCancel := context.WithCancel(c.ctx)
	bundle := &h2Bundle{
		addr:    edgeAddr,
		netConn: tlsConn,
		client:  clientConn,
		cancel:  lifeCancel,
		failed:  make(chan error, 1),
		done:    make(chan struct{}),
	}

	headers := make(http.Header)
	headers.Set("User-Agent", "")
	headers.Set("cf-connect-proto", "cf-connect-ip")
	headers.Set("pq-enabled", "false")

	type connectResult struct {
		conn *connectip.Conn
		resp *http.Response
		err  error
	}
	resultCh := make(chan connectResult, 1)
	go func() {
		conn, resp, err := connectip.DialH2(
			lifeCtx,
			&http.Client{Transport: clientConn},
			h2ConnectTemplate,
			headers,
		)
		resultCh <- connectResult{conn: conn, resp: resp, err: err}
	}()

	timer := time.NewTimer(h2ConnectTimeout)
	defer timer.Stop()
	select {
	case result := <-resultCh:
		if result.err != nil {
			bundle.close()
			return nil, fmt.Errorf("CONNECT-IP 失败：%w", result.err)
		}
		bundle.ipConn = result.conn
		status := "unknown"
		if result.resp != nil {
			status = result.resp.Status
		}
		log.Printf("HTTP/2 CONNECT-IP 已建立（endpoint=%s，status=%s，ALPN=%s，MTU=%d）",
			edgeAddr, status, negotiated, h2MTU)
		return bundle, nil
	case <-setupCtx.Done():
		bundle.close()
		return nil, context.Cause(setupCtx)
	case <-c.ctx.Done():
		bundle.close()
		return nil, net.ErrClosed
	case <-timer.C:
		bundle.close()
		return nil, errors.New("HTTP/2 CONNECT-IP 初始化超时")
	}
}

func (c *H2Client) setCurrent(bundle *h2Bundle) bool {
	c.connMu.Lock()
	defer c.connMu.Unlock()
	if c.closed || c.ctx.Err() != nil {
		return false
	}
	c.current = bundle
	close(c.connChanged)
	c.connChanged = make(chan struct{})
	return true
}

func (c *H2Client) clearCurrent(bundle *h2Bundle) {
	c.connMu.Lock()
	defer c.connMu.Unlock()
	if c.current != bundle {
		return
	}
	c.current = nil
	close(c.connChanged)
	c.connChanged = make(chan struct{})
}

func (c *H2Client) waitCurrent(ctx context.Context) (*h2Bundle, error) {
	for {
		c.connMu.Lock()
		if c.closed {
			c.connMu.Unlock()
			return nil, net.ErrClosed
		}
		if c.current != nil {
			bundle := c.current
			c.connMu.Unlock()
			return bundle, nil
		}
		changed := c.connChanged
		c.connMu.Unlock()

		select {
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		case <-c.ctx.Done():
			return nil, net.ErrClosed
		case <-changed:
		}
	}
}

func (c *H2Client) outboundPump() {
	buffer := make([]byte, h2PacketBufferSize)
	packetBuffers := [][]byte{buffer[h2PacketHeadroom:]}
	sizes := []int{0}

	for {
		_, err := c.tunDev.Read(packetBuffers, sizes, 0)
		if err != nil {
			if c.ctx.Err() == nil {
				log.Printf("H2 netstack 出站读取失败：%v", err)
			}
			return
		}
		n := sizes[0]
		if n <= 0 || n > h2MTU {
			continue
		}

		bundle, err := c.waitCurrent(c.ctx)
		if err != nil {
			return
		}
		icmp, err := bundle.ipConn.WritePacketBuffer(buffer, h2PacketHeadroom, n)
		if err != nil {
			bundle.fail(fmt.Errorf("发送 IP 包失败：%w", err))
			continue
		}
		if len(icmp) > 0 {
			_, err = c.tunDev.Write([][]byte{icmp}, 0)
			if err != nil && c.ctx.Err() == nil {
				log.Printf("H2 netstack 写入 ICMP 失败：%v", err)
			}
		}
	}
}

func (c *H2Client) maintain(bundle *h2Bundle) {
	for {
		var bundleWG sync.WaitGroup
		bundleWG.Add(2)
		go func() {
			defer bundleWG.Done()
			c.inboundPump(bundle)
		}()
		go func() {
			defer bundleWG.Done()
			c.keepalive(bundle)
		}()

		var failure error
		select {
		case <-c.ctx.Done():
			failure = net.ErrClosed
		case failure = <-bundle.failed:
		}

		c.clearCurrent(bundle)
		bundle.close()
		bundleWG.Wait()
		if c.ctx.Err() != nil {
			return
		}
		log.Printf("HTTP/2 CONNECT-IP 连接丢失（%v），正在重连 ...", failure)

		for {
			select {
			case <-c.ctx.Done():
				return
			case <-time.After(h2ReconnectDelay):
			}
			newBundle, err := c.dial(c.ctx)
			if err != nil {
				if c.ctx.Err() != nil {
					return
				}
				log.Printf("HTTP/2 CONNECT-IP 重连失败：%v", err)
				continue
			}
			if !c.setCurrent(newBundle) {
				newBundle.close()
				return
			}
			bundle = newBundle
			log.Println("HTTP/2 CONNECT-IP 已重建")
			break
		}
	}
}

func (c *H2Client) inboundPump(bundle *h2Bundle) {
	for {
		packet, err := bundle.ipConn.ReadPacketZeroCopy(true)
		if err != nil {
			select {
			case <-bundle.done:
				return
			default:
				bundle.fail(fmt.Errorf("接收 IP 包失败：%w", err))
				return
			}
		}
		if len(packet) == 0 {
			continue
		}
		if _, err := c.tunDev.Write([][]byte{packet}, 0); err != nil {
			if c.ctx.Err() == nil {
				bundle.fail(fmt.Errorf("写入用户态网络栈失败：%w", err))
			}
			return
		}
	}
}

func (c *H2Client) keepalive(bundle *h2Bundle) {
	ticker := time.NewTicker(h2PingPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-bundle.done:
			return
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(c.ctx, h2PingTimeout)
			err := bundle.client.Ping(ctx)
			cancel()
			if err != nil {
				bundle.fail(fmt.Errorf("HTTP/2 PING 失败：%w", err))
				return
			}
		}
	}
}

func (c *H2Client) Close() error {
	c.closeOnce.Do(func() {
		c.connMu.Lock()
		c.closed = true
		bundle := c.current
		c.current = nil
		close(c.connChanged)
		c.connChanged = make(chan struct{})
		c.connMu.Unlock()

		c.cancel()
		bundle.close()
		_ = c.tunDev.Close()
		c.wg.Wait()
	})
	return nil
}
