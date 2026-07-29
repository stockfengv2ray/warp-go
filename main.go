package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/proxy"

	"warp/registration"
	"warp/tunnel"
)

// defaultStateFile holds the registration: keys, token, edge endpoint and the
// edge public key that the connection is pinned to.
const defaultStateFile = "reg.json"

// usage replaces the flag package's default listing. That listing sorts
// alphabetically, which puts the destructive -del first and buries -l, and it
// has nowhere to explain the H3/H2 UDP distinction or that the default listen
// address is world-reachable with no authentication.
func usage() {
	out := flag.CommandLine.Output()
	fmt.Fprint(out, `warp —— Cloudflare WARP 客户端（MASQUE H3/H2，SOCKS5 前端）

用法：
  warp [选项]

代理：
  -l <host:port>   SOCKS5 监听地址（默认 :40000，同时接受 IPv4 与 IPv6 客户端）
  -user <用户名>   SOCKS5 用户名；必须同时给出 -user 和 -pass 才启用认证
  -pass <密码>     SOCKS5 密码
  -transport <值>  传输方式（默认 auto）：
                     auto  先尝试 QUIC/HTTP-3，失败后改用 TCP/HTTP-2
                     h3    plain CONNECT over QUIC/HTTP-3（TCP 经过 WARP）
                     h2    CONNECT-IP over TCP/HTTP-2（TCP、UDP、DNS 均经过 WARP）
  -ip <取值>       连接哪个边缘（默认 4）：
                     4            注册信息中的 IPv4 边缘
                     6            注册信息中的 IPv6 边缘
                     <host:port>  改为连接指定地址，例如 162.159.198.2:4500、
                                  [2606:4700:103::2]:443、example.com:443
                   它决定的是"如何到达边缘"，不限制隧道内能访问什么 —— 目标
                   由边缘代为连接，所以走 IPv4 边缘一样能访问 IPv6-only 站点。
                   取 4 或 6 时会遍历注册给出的整个端口列表；给显式 host:port
                   时只使用该端口。域名由系统解析器解析（此时隧道尚未建立），
                   解析出的每个地址都会作为候选。

注册：
  -reg             尚未注册时执行注册，然后退出
  -del             向 API 注销并删除本地注册信息

注册信息保存在工作目录下的 reg.json。首次使用需先注册：启动本身从不注册，
因为创建账号是一个需要明确表达的动作。-reg 是幂等的 —— 已有注册时只报告并
退出，而不是替换掉它；替换会让旧注册在 Cloudflare 侧失去本地凭据，再也无法
注销。要更换注册，请先用 -del。

边缘地址与端口列表来自注册信息，因此没有单独的端点参数；端口按 API 返回的
顺序尝试，并从上次成功的那个开始。

示例：
  warp -reg                               注册（首次使用）
  warp                                    用已保存的注册信息运行
  warp -ip 6                              通过 IPv6 连接边缘
  warp -ip 162.159.198.2:4500             指定边缘地址与端口
  warp -ip example.com:443                通过域名连接自定义边缘
  warp -transport h2                      使用 Railway 兼容的 TCP/HTTP-2
  warp -l 127.0.0.1:1080                  只监听回环地址
  warp -l 0.0.0.0:1080 -user u -pass s    对外提供服务并要求认证
  warp -del && warp -reg                  更换注册

注意：
  h3 后端的 UDP ASSOCIATE 数据报不经过 WARP；plain CONNECT 只能承载字节流。
  h2 后端使用 CONNECT-IP 和用户态网络栈，TCP、UDP 与代理域名解析都经过 WARP。

  默认监听地址接受来自任何位置的连接，且不要求认证。在不可信网络中请绑定
  回环地址（-l 127.0.0.1:40000），或设置 -user 与 -pass。

`)
}

// edgeLookupTimeout bounds the bootstrap name lookup for an -ip hostname.
const edgeLookupTimeout = 10 * time.Second

// resolveEdge turns an explicit -ip value into the candidate address list.
//
// A hostname has to be resolved by the system resolver: this runs before the
// tunnel exists, so the in-tunnel DoH client is not available yet. That means a
// hostname here is visible to the local resolver — the same exposure the
// registration API call already has, but worth knowing about. An IP literal
// avoids it entirely.
//
// Every address the name resolves to becomes a candidate, so a dual-stack
// hostname still works on a single-stack host: the families this host cannot
// route are rejected immediately by the dialer.
func resolveEdge(spec string) ([]string, error) {
	host, port, err := net.SplitHostPort(spec)
	if err != nil {
		return nil, fmt.Errorf("需要 host:port 形式，例如 162.159.198.2:443、"+
			"[2606:4700:103::2]:443 或 example.com:443（%w）", err)
	}
	if host == "" {
		return nil, errors.New("需要 host:port 形式，主机部分为空")
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return nil, fmt.Errorf("端口 %q 不是 1-65535 范围内的数字", port)
	}

	if net.ParseIP(host) != nil {
		return []string{net.JoinHostPort(host, port)}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), edgeLookupTimeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("用系统解析器解析 %q 失败：%w", host, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("%q 未解析出任何地址", host)
	}

	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, net.JoinHostPort(a.IP.String(), port))
	}
	return out, nil
}

type socksBackend interface {
	HandleSOCKS5(context.Context, net.Conn, tunnel.SOCKS5Config)
	Close() error
}

func loopbackAddress(listener net.Listener) string {
	addr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		return listener.Addr().String()
	}
	ip := addr.IP
	if ip == nil || ip.IsUnspecified() {
		ip = net.IPv4(127, 0, 0, 1)
		if addr.IP != nil && addr.IP.To4() == nil {
			ip = net.IPv6loopback
		}
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(addr.Port))
}

func runSOCKSSelfTest(ctx context.Context, address, username, password string) error {
	var auth *proxy.Auth
	if username != "" && password != "" {
		auth = &proxy.Auth{User: username, Password: password}
	}
	dialer, err := proxy.SOCKS5("tcp", address, auth, proxy.Direct)
	if err != nil {
		return fmt.Errorf("创建 SOCKS5 测试拨号器失败：%w", err)
	}

	transport := &http.Transport{
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: 10 * time.Second,
		DialContext: func(dialCtx context.Context, network, target string) (net.Conn, error) {
			if contextDialer, ok := dialer.(proxy.ContextDialer); ok {
				return contextDialer.DialContext(dialCtx, network, target)
			}
			return dialer.Dial(network, target)
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://www.cloudflare.com/cdn-cgi/trace", nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("经 SOCKS5 请求 trace 失败：%w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return fmt.Errorf("读取 trace 失败：%w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("trace 返回 %s：%s", resp.Status, strings.TrimSpace(string(body)))
	}

	values := make(map[string]string)
	for _, line := range strings.Split(string(body), "\n") {
		key, value, found := strings.Cut(line, "=")
		if found {
			values[key] = strings.TrimSpace(value)
		}
	}
	if values["warp"] != "on" && values["warp"] != "plus" {
		return fmt.Errorf("trace 未确认 WARP：warp=%q ip=%q colo=%q",
			values["warp"], values["ip"], values["colo"])
	}
	log.Printf("SOCKS 数据面验证成功（warp=%s，ip=%s，colo=%s）",
		values["warp"], values["ip"], values["colo"])
	return nil
}

func main() {
	var (
		listen    = flag.String("l", ":40000", "SOCKS5 监听地址 host:port")
		user      = flag.String("user", "", "SOCKS5 用户名（与 -pass 同时给出才启用认证）")
		pass      = flag.String("pass", "", "SOCKS5 密码（与 -user 同时给出才启用认证）")
		ip        = flag.String("ip", "4", "WARP 边缘：4、6，或显式 host:port")
		transport = flag.String("transport", "auto", "传输：auto、h3 或 h2")
		selfTest  = flag.Bool("self-test", false, "启动后通过本地 SOCKS5 验证 warp=on")
		reg       = flag.Bool("reg", false, "尚未注册时执行注册，然后退出")
		del       = flag.Bool("del", false, "向 API 注销并删除本地注册信息")
	)
	flag.Usage = usage
	flag.Parse()
	*transport = strings.ToLower(strings.TrimSpace(*transport))
	if *transport != "auto" && *transport != "h3" && *transport != "h2" {
		log.Fatalf("-transport 只接受 auto、h3 或 h2，收到 %q", *transport)
	}

	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	// -del and -reg are administrative: each does its one job and exits, so that
	// registering cannot be confused with starting the proxy.
	if *del {
		log.Println("正在注销...")
		if err := registration.DeleteRegistration(defaultStateFile); err != nil {
			log.Fatalf("注销失败：%v", err)
		}
		log.Println("✓ 注销成功")
		return
	}

	if *reg {
		// Registering is idempotent: an existing registration is left alone.
		// Replacing it silently would strand the old one on Cloudflare's side
		// with no local credential left to delete it.
		switch existing, err := registration.Load(defaultStateFile); {
		case err == nil:
			log.Printf("已注册：id=%s（%s）", existing.ID, defaultStateFile)
			log.Println("无需操作。要换一个注册，请先用 -del 注销。")
			return
		case !errors.Is(err, fs.ErrNotExist):
			log.Fatalf("%s 存在但无法读取（%v）。\n"+
				"拒绝覆盖：请删除该文件，或先执行 -del。", defaultStateFile, err)
		}

		regData, err := registration.Register()
		if err != nil {
			log.Fatalf("注册失败：%v", err)
		}
		if err := regData.Save(defaultStateFile); err != nil {
			log.Fatalf("注册信息写入 %s 失败：%v", defaultStateFile, err)
		}
		log.Printf("✓ 注册信息已保存到 %s（id=%s）", defaultStateFile, regData.ID)
		log.Println("不带 -reg 运行即可启动代理。")
		return
	}

	// Starting never registers: creating an account is an explicit act, and
	// doing it implicitly would leave a registration on Cloudflare's side that
	// the user never asked for.
	regData, err := registration.Load(defaultStateFile)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			log.Fatalf("%s 中没有注册信息。请先执行 warp -reg。", defaultStateFile)
		}
		log.Fatalf("无法读取注册文件 %s：%v", defaultStateFile, err)
	}
	log.Printf("✓ 已注册：id=%s", regData.ID)

	// H3 uses the registration's UDP port list. H2 CONNECT-IP is a TCP service
	// verified on port 443, so family selection uses the same endpoint host but
	// does not blindly try the UDP-only candidate ports.
	var h3EdgeAddrs, h2EdgeAddrs []string
	switch *ip {
	case "4", "6":
		endpointHost, other := regData.EndpointV4, "6"
		if *ip == "6" {
			endpointHost, other = regData.EndpointV6, "4"
		}
		if endpointHost == "" {
			log.Fatalf("注册信息中没有 IPv%s 边缘地址。"+
				"可改用 -ip %s，或依次执行 -del 与 -reg 重新注册。", *ip, other)
		}

		ports := regData.EndpointPorts
		if len(ports) == 0 {
			ports = []int{443}
		}
		for _, p := range ports {
			h3EdgeAddrs = append(h3EdgeAddrs, net.JoinHostPort(endpointHost, strconv.Itoa(p)))
		}
		h2EdgeAddrs = []string{net.JoinHostPort(endpointHost, "443")}
		log.Printf("WARP 代理启动中（transport=%s，边缘=IPv%s %s，H3端口=%v，H2端口=443，socks5=%s）",
			*transport, *ip, endpointHost, ports, *listen)

	default:
		var err error
		if h3EdgeAddrs, err = resolveEdge(*ip); err != nil {
			log.Fatalf("-ip %q 既不是 4 或 6，也不是可用地址：%v", *ip, err)
		}
		h2EdgeAddrs = append([]string(nil), h3EdgeAddrs...)
		log.Printf("WARP 代理启动中（transport=%s，边缘=%s → %v，socks5=%s）",
			*transport, *ip, h3EdgeAddrs, *listen)
	}

	// Pin the edge to the endpoint public key from registration, like warp-svc does.
	verifyEdge, err := regData.PeerPublicKeyVerifier()
	if err != nil {
		log.Fatalf("边缘公钥固定初始化失败：%v", err)
	}

	// Build the common TLS identity and pinning policy. Each backend sets its own
	// SNI and protocol list on a clone.
	// The SNI is a well-known name rather than the edge's own identity and the
	// chain is signed by a private CA, so the standard chain check cannot apply;
	// authentication comes from pinning the endpoint public key instead.
	baseTLSConfig := &tls.Config{
		InsecureSkipVerify:    true,
		MinVersion:            tls.VersionTLS13,
		Certificates:          []tls.Certificate{regData.ClientCert},
		VerifyPeerCertificate: verifyEdge,

		// warp-svc offers only the NIST curves — its ClientCertificateHook sets
		// P-256/P-384/P-521 and never X25519. Go would otherwise lead with
		// X25519, and the edge answers a key share it does not want with a
		// HelloRetryRequest, costing an extra round trip on every handshake.
		CurvePreferences: []tls.CurveID{tls.CurveP256, tls.CurveP384, tls.CurveP521},
	}
	if verifyEdge != nil {
		log.Println("✓ 边缘公钥固定已启用")
	} else {
		log.Println("⚠ 注册信息中没有边缘公钥，公钥固定已禁用（请重新执行 -reg）")
	}

	newH3Client := func(ctx context.Context) (*tunnel.MasqueClient, error) {
		tlsConfig := baseTLSConfig.Clone()
		tlsConfig.ServerName = "consumer-masque-proxy.cloudflareclient.com"
		tlsConfig.NextProtos = []string{"h3"}
		return tunnel.NewMasqueClientContext(ctx, h3EdgeAddrs, tlsConfig, regData.Token)
	}
	newH2Client := func(ctx context.Context) (*tunnel.H2Client, error) {
		return tunnel.NewH2ClientContext(ctx, h2EdgeAddrs, baseTLSConfig,
			regData.AssignedIPv4, regData.AssignedIPv6)
	}

	var proxyClient socksBackend
	selectedTransport := *transport
	switch *transport {
	case "h3":
		proxyClient, err = newH3Client(context.Background())
	case "h2":
		setupCtx, cancelSetup := context.WithTimeout(context.Background(), 30*time.Second)
		proxyClient, err = newH2Client(setupCtx)
		cancelSetup()
	case "auto":
		const autoH3Budget = 10 * time.Second
		h3Ctx, cancelH3 := context.WithTimeout(context.Background(), autoH3Budget)
		proxyClient, err = newH3Client(h3Ctx)
		cancelH3()
		if err == nil {
			selectedTransport = "h3"
			break
		}
		log.Printf("H3 初始连接在 %s 内失败（%v），切换到 HTTP/2 CONNECT-IP ...",
			autoH3Budget, err)
		setupCtx, cancelSetup := context.WithTimeout(context.Background(), 30*time.Second)
		proxyClient, err = newH2Client(setupCtx)
		cancelSetup()
		selectedTransport = "h2"
	}
	if err != nil {
		log.Fatalf("MASQUE %s 连接失败：%v", selectedTransport, err)
	}
	defer proxyClient.Close()
	log.Printf("✓ MASQUE 连接已建立（transport=%s）", selectedTransport)

	// Start SOCKS5 proxy server
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("SOCKS5 监听失败：%v", err)
	}
	defer ln.Close()

	socksCfg := tunnel.SOCKS5Config{
		Username: *user,
		Password: *pass,
		AllowUDP: true,
	}

	authInfo := ""
	if *user != "" && *pass != "" {
		authInfo = fmt.Sprintf("（认证用户：%s）", *user)
	}
	log.Printf("SOCKS5 代理监听于 %s%s", ln.Addr(), authInfo)
	if selectedTransport == "h2" {
		log.Println("UDP ASSOCIATE 已启用 —— 数据报和 DNS 均经过 WARP CONNECT-IP")
	} else {
		log.Println("UDP ASSOCIATE 已启用 —— H3 数据报从本机直接发出，不经过 WARP")
	}

	// Handle connections
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if *selfTest {
		testAddress := loopbackAddress(ln)
		go func() {
			var testErr error
			for attempt := 1; attempt <= 3; attempt++ {
				testErr = runSOCKSSelfTest(ctx, testAddress, *user, *pass)
				if testErr == nil {
					return
				}
				log.Printf("SOCKS 数据面验证第 %d 次失败：%v", attempt, testErr)
				select {
				case <-ctx.Done():
					return
				case <-time.After(2 * time.Second):
				}
			}
			log.Printf("SOCKS 数据面验证失败：%v", testErr)
		}()
	}

	go func() {
		<-sigCh
		log.Println("正在关闭...")
		cancel()   // signal all HandleSOCKS5 goroutines to stop
		ln.Close() // unblock Accept
	}()

	// Accept errors are not all fatal. Running out of file descriptors or having
	// a client vanish between the SYN and the accept is transient: backing off
	// and continuing keeps the proxy alive, where returning would take the whole
	// process down over a momentary condition.
	const maxAcceptBackoff = time.Second
	var acceptBackoff time.Duration

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break // graceful shutdown
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			if errors.Is(err, net.ErrClosed) {
				break // listener gone and not a shutdown we initiated
			}
			if acceptBackoff == 0 {
				acceptBackoff = 5 * time.Millisecond
			} else if acceptBackoff *= 2; acceptBackoff > maxAcceptBackoff {
				acceptBackoff = maxAcceptBackoff
			}
			log.Printf("Accept 出错：%v，%s 后重试", err, acceptBackoff)
			select {
			case <-time.After(acceptBackoff):
			case <-ctx.Done():
				return
			}
			continue
		}
		acceptBackoff = 0
		go proxyClient.HandleSOCKS5(ctx, conn, socksCfg)
	}
}
