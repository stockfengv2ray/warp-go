package tunnel

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"time"
)

const socks5HandshakeTimeout = 15 * time.Second

// HandleSOCKS5 serves one SOCKS connection through the userspace CONNECT-IP
// stack. Unlike the H3 plain-CONNECT backend, both TCP and UDP stay in WARP.
func (c *H2Client) HandleSOCKS5(ctx context.Context, conn net.Conn, cfg SOCKS5Config) {
	defer conn.Close()

	handlerDone := make(chan struct{})
	defer close(handlerDone)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-handlerDone:
		}
	}()

	_ = conn.SetDeadline(time.Now().Add(socks5HandshakeTimeout))
	if err := negotiateSOCKS5(conn, cfg); err != nil {
		return
	}

	command, targetAddr, err := readSOCKS5Request(conn)
	if err != nil {
		sendSocks5Err(conn, 0x08)
		return
	}

	switch command {
	case socks5CmdConnect:
		// handled below
	case socks5CmdUDPAssociate:
		if !cfg.AllowUDP {
			sendSocks5Err(conn, 0x07)
			return
		}
		_ = conn.SetDeadline(time.Time{})
		c.handleH2UDPAssociate(ctx, conn)
		return
	default:
		sendSocks5Err(conn, 0x07)
		return
	}

	_, port, err := net.SplitHostPort(targetAddr)
	if err != nil || port == "0" {
		sendSocks5Err(conn, 0x08)
		return
	}

	log.Printf("SOCKS5 CONNECT %s（HTTP/2 CONNECT-IP）", targetAddr)
	_ = conn.SetDeadline(time.Time{})
	setupCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
	remote, err := c.tunNet.DialContext(setupCtx, "tcp", targetAddr)
	cancel()
	if err != nil {
		log.Printf("H2 netstack 连接 %s 失败：%v", targetAddr, err)
		sendSocks5Err(conn, socks5ReplyForError(err))
		return
	}
	defer remote.Close()

	if err := writeSocks5Success(conn); err != nil {
		return
	}
	log.Printf("WARP IP 隧道已建立：%s", targetAddr)

	done := make(chan error, 2)
	go func() {
		_, copyErr := io.Copy(conn, remote)
		done <- copyErr
	}()
	go func() {
		_, copyErr := io.Copy(remote, conn)
		done <- copyErr
	}()

	<-done
	_ = conn.Close()
	_ = remote.Close()
	<-done
	log.Printf("WARP IP 隧道已关闭：%s", targetAddr)
}

func negotiateSOCKS5(conn net.Conn, cfg SOCKS5Config) error {
	var header [2]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return err
	}
	if header[0] != 0x05 || header[1] == 0 {
		return errors.New("非法 SOCKS5 方法协商")
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	requireAuth := cfg.Username != "" && cfg.Password != ""
	selected := byte(0x00)
	if requireAuth {
		selected = 0x02
	}
	offered := false
	for _, method := range methods {
		if method == selected {
			offered = true
			break
		}
	}
	if !offered {
		_, _ = conn.Write([]byte{0x05, 0xff})
		return errors.New("客户端未提供所需 SOCKS5 认证方式")
	}
	if _, err := conn.Write([]byte{0x05, selected}); err != nil {
		return err
	}
	if !requireAuth {
		return nil
	}

	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return err
	}
	if header[0] != 0x01 || header[1] == 0 {
		_, _ = conn.Write([]byte{0x01, 0x01})
		return errors.New("非法 SOCKS5 用户名认证请求")
	}
	username := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, username); err != nil {
		return err
	}
	var passwordLength [1]byte
	if _, err := io.ReadFull(conn, passwordLength[:]); err != nil {
		return err
	}
	password := make([]byte, int(passwordLength[0]))
	if _, err := io.ReadFull(conn, password); err != nil {
		return err
	}

	userOK := subtle.ConstantTimeCompare(username, []byte(cfg.Username))
	passOK := subtle.ConstantTimeCompare(password, []byte(cfg.Password))
	if userOK&passOK != 1 {
		_, _ = conn.Write([]byte{0x01, 0x01})
		return errors.New("SOCKS5 用户名或密码错误")
	}
	_, err := conn.Write([]byte{0x01, 0x00})
	return err
}

func readSOCKS5Request(conn net.Conn) (command byte, target string, err error) {
	var header [4]byte
	if _, err = io.ReadFull(conn, header[:]); err != nil {
		return 0, "", err
	}
	if header[0] != 0x05 || header[2] != 0x00 {
		return 0, "", errors.New("非法 SOCKS5 请求头")
	}

	var host string
	switch header[3] {
	case 0x01:
		value := make([]byte, net.IPv4len)
		if _, err = io.ReadFull(conn, value); err != nil {
			return 0, "", err
		}
		host = net.IP(value).String()
	case 0x03:
		var length [1]byte
		if _, err = io.ReadFull(conn, length[:]); err != nil {
			return 0, "", err
		}
		if length[0] == 0 {
			return 0, "", errors.New("SOCKS5 目标域名为空")
		}
		value := make([]byte, int(length[0]))
		if _, err = io.ReadFull(conn, value); err != nil {
			return 0, "", err
		}
		host = string(value)
	case 0x04:
		value := make([]byte, net.IPv6len)
		if _, err = io.ReadFull(conn, value); err != nil {
			return 0, "", err
		}
		host = net.IP(value).String()
	default:
		return 0, "", fmt.Errorf("未知 SOCKS5 地址类型：%d", header[3])
	}

	var portBytes [2]byte
	if _, err = io.ReadFull(conn, portBytes[:]); err != nil {
		return 0, "", err
	}
	port := int(portBytes[0])<<8 | int(portBytes[1])
	return header[1], net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func writeSocks5Success(conn net.Conn) error {
	_, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	return err
}

func socks5ReplyForError(err error) byte {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return 0x04
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return 0x04
	}
	return 0x05
}
