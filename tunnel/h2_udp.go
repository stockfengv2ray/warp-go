package tunnel

import (
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"
	"time"
)

type h2UDPRemote struct {
	family int
	conn   net.PacketConn
}

type h2UDPAssociation struct {
	client  *net.UDPConn
	remotes []h2UDPRemote

	mu         sync.Mutex
	clientAddr *net.UDPAddr
}

func (a *h2UDPAssociation) peer() *net.UDPAddr {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.clientAddr
}

func (a *h2UDPAssociation) setPeer(addr *net.UDPAddr) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.clientAddr == nil {
		a.clientAddr = addr
		return true
	}
	return a.clientAddr.IP.Equal(addr.IP) && a.clientAddr.Port == addr.Port
}

func (a *h2UDPAssociation) remoteFor(ip net.IP) net.PacketConn {
	family := 6
	if ip.To4() != nil {
		family = 4
	}
	for _, remote := range a.remotes {
		if remote.family == family {
			return remote.conn
		}
	}
	return nil
}

func (a *h2UDPAssociation) close() {
	_ = a.client.Close()
	for _, remote := range a.remotes {
		_ = remote.conn.Close()
	}
}

func (c *H2Client) handleH2UDPAssociate(ctx context.Context, conn net.Conn) {
	tcpLocal, ok := conn.LocalAddr().(*net.TCPAddr)
	if !ok {
		sendSocks5Err(conn, 0x01)
		return
	}
	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: tcpLocal.IP, Port: 0})
	if err != nil {
		log.Printf("H2 UDP ASSOCIATE：绑定客户端 socket 失败：%v", err)
		sendSocks5Err(conn, 0x01)
		return
	}

	association := &h2UDPAssociation{client: clientConn}
	if c.local4 != nil {
		remote, listenErr := c.tunNet.ListenUDP(&net.UDPAddr{IP: c.local4, Port: 0})
		if listenErr != nil {
			association.close()
			log.Printf("H2 UDP ASSOCIATE：创建 IPv4 WARP socket 失败：%v", listenErr)
			sendSocks5Err(conn, 0x01)
			return
		}
		association.remotes = append(association.remotes, h2UDPRemote{family: 4, conn: remote})
	}
	if c.local6 != nil {
		remote, listenErr := c.tunNet.ListenUDP(&net.UDPAddr{IP: c.local6, Port: 0})
		if listenErr != nil {
			association.close()
			log.Printf("H2 UDP ASSOCIATE：创建 IPv6 WARP socket 失败：%v", listenErr)
			sendSocks5Err(conn, 0x01)
			return
		}
		association.remotes = append(association.remotes, h2UDPRemote{family: 6, conn: remote})
	}
	if len(association.remotes) == 0 {
		association.close()
		sendSocks5Err(conn, 0x01)
		return
	}
	defer association.close()

	bound, ok := clientConn.LocalAddr().(*net.UDPAddr)
	if !ok {
		sendSocks5Err(conn, 0x01)
		return
	}
	if err := sendSocks5Bound(conn, bound.IP, bound.Port); err != nil {
		return
	}
	log.Printf("SOCKS5 UDP ASSOCIATE 中继于 %s（经过 WARP HTTP/2 CONNECT-IP）", bound)

	stop := make(chan struct{})
	var stopOnce sync.Once
	shutdown := func() {
		stopOnce.Do(func() {
			close(stop)
			association.close()
		})
	}

	go func() {
		select {
		case <-ctx.Done():
		case <-stop:
		}
		shutdown()
	}()
	go func() {
		buffer := make([]byte, 256)
		for {
			if _, readErr := conn.Read(buffer); readErr != nil {
				shutdown()
				return
			}
		}
	}()

	var wg sync.WaitGroup
	wg.Add(1 + len(association.remotes))
	go func() {
		defer wg.Done()
		defer shutdown()
		c.h2UDPClientToRemote(ctx, association)
	}()
	for _, remote := range association.remotes {
		remote := remote
		go func() {
			defer wg.Done()
			defer shutdown()
			c.h2UDPRemoteToClient(association, remote.conn)
		}()
	}
	wg.Wait()
	log.Printf("SOCKS5 UDP ASSOCIATE 已关闭（%s）", bound)
}

func (c *H2Client) h2UDPClientToRemote(ctx context.Context, association *h2UDPAssociation) {
	bufferPointer := udpBufPool.Get().(*[]byte)
	defer udpBufPool.Put(bufferPointer)
	buffer := *bufferPointer

	for {
		if err := association.client.SetReadDeadline(time.Now().Add(udpIdleTimeout)); err != nil {
			return
		}
		n, source, err := association.client.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		if !association.setPeer(source) {
			continue
		}

		destination, payload, err := parseUDPRequest(buffer[:n])
		if err != nil {
			continue
		}
		resolveCtx, cancel := context.WithTimeout(ctx, udpResolveTimeout)
		target, err := c.resolveH2UDPTarget(resolveCtx, destination, association)
		cancel()
		if err != nil {
			log.Printf("H2 UDP 目标解析失败：%v", err)
			continue
		}
		remote := association.remoteFor(target.IP)
		if remote == nil {
			continue
		}
		_ = remote.SetWriteDeadline(time.Now().Add(udpIdleTimeout))
		if _, err := remote.WriteTo(payload, target); err != nil {
			continue
		}
	}
}

func (c *H2Client) resolveH2UDPTarget(ctx context.Context, destination string, association *h2UDPAssociation) (*net.UDPAddr, error) {
	host, portValue, err := net.SplitHostPort(destination)
	if err != nil {
		return nil, fmt.Errorf("非法 UDP 目标 %q：%w", destination, err)
	}
	port, err := strconv.Atoi(portValue)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("非法 UDP 端口 %q", portValue)
	}
	if ip := net.ParseIP(host); ip != nil {
		if association.remoteFor(ip) == nil {
			return nil, fmt.Errorf("没有可用的 IPv%d WARP UDP socket", ipFamily(ip))
		}
		return &net.UDPAddr{IP: ip, Port: port}, nil
	}

	addresses, err := c.tunNet.LookupContextHost(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("在 WARP 内解析 %q 失败：%w", host, err)
	}
	for _, value := range addresses {
		ip := net.ParseIP(value)
		if ip != nil && association.remoteFor(ip) != nil {
			return &net.UDPAddr{IP: ip, Port: port}, nil
		}
	}
	return nil, fmt.Errorf("%q 没有与可用 WARP UDP socket 匹配的地址", host)
}

func ipFamily(ip net.IP) int {
	if ip.To4() != nil {
		return 4
	}
	return 6
}

func (c *H2Client) h2UDPRemoteToClient(association *h2UDPAssociation, remote net.PacketConn) {
	bufferPointer := udpBufPool.Get().(*[]byte)
	defer udpBufPool.Put(bufferPointer)
	buffer := *bufferPointer
	framePointer := udpBufPool.Get().(*[]byte)
	defer udpBufPool.Put(framePointer)

	for {
		if err := remote.SetReadDeadline(time.Now().Add(udpIdleTimeout)); err != nil {
			return
		}
		n, source, err := remote.ReadFrom(buffer)
		if err != nil {
			return
		}
		peer := association.peer()
		if peer == nil {
			continue
		}
		udpSource, ok := source.(*net.UDPAddr)
		if !ok {
			continue
		}
		frame, err := appendUDPReply((*framePointer)[:0], udpSource, buffer[:n])
		if err != nil {
			continue
		}
		if _, err := association.client.WriteToUDP(frame, peer); err != nil {
			return
		}
	}
}
