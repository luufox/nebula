package nebula

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/slackhq/nebula/config"
)

const (
	socks5Version          = 5
	socks5NoAuthentication = 0
	proxyHandshakeTimeout  = 10 * time.Second
)

// proxyServer is a TCP proxy which accepts SOCKS5 and HTTP proxy requests.
// It is bound exclusively to a Nebula address so it is reachable only through
// the Nebula network, unless routes or host firewall rules make it available
// elsewhere.
type proxyServer struct {
	l *slog.Logger

	mu         sync.Mutex
	addr       string
	cancel     context.CancelFunc
	listener   net.Listener
	clients    map[net.Conn]struct{}
	generation uint64
}

func newProxyServer(l *slog.Logger) *proxyServer {
	return &proxyServer{
		l:       l.With("subsystem", "socks5"),
		clients: make(map[net.Conn]struct{}),
	}
}

// proxyMain returns the delayed starter used by Control.Start. Configuration
// reloads restart the listener only when socks5.port changes.
func proxyMain(ctx context.Context, l *slog.Logger, vpnAddr netip.Addr, c *config.C) (func(), error) {
	p := newProxyServer(l)

	configure := func(c *config.C, logInvalid bool) error {
		addr, enabled, err := proxyAddress(vpnAddr, c)
		if err != nil {
			if logInvalid {
				l.Error("Invalid SOCKS5 proxy configuration; keeping the current listener", "error", err)
				return nil
			}
			return err
		}

		if !enabled {
			p.Stop()
			return nil
		}

		p.Start(ctx, addr)
		return nil
	}

	if _, _, err := proxyAddress(vpnAddr, c); err != nil {
		return nil, err
	}

	c.RegisterReloadCallback(func(c *config.C) {
		_ = configure(c, true)
	})

	return func() {
		if err := configure(c, false); err != nil {
			l.Error("Failed to start SOCKS5 proxy", "error", err)
		}
	}, nil
}

func proxyAddress(vpnAddr netip.Addr, c *config.C) (addr string, enabled bool, err error) {
	rawPort := c.GetString("socks5.port", "")
	if rawPort == "" {
		return "", false, nil
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		return "", false, fmt.Errorf("socks5.port must be an integer: %w", err)
	}
	if port < 1 || port > 65535 {
		return "", false, fmt.Errorf("socks5.port must be between 1 and 65535, got %d", port)
	}

	return net.JoinHostPort(vpnAddr.String(), strconv.Itoa(port)), true, nil
}

// Start makes addr active. It is safe to call repeatedly and from config
// reload callbacks; a changed address replaces the old listener and clients.
func (p *proxyServer) Start(parent context.Context, addr string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.addr == addr && p.cancel != nil {
		return
	}
	p.stopLocked()

	ctx, cancel := context.WithCancel(parent)
	p.addr = addr
	p.cancel = cancel
	p.generation++
	generation := p.generation
	go p.serve(ctx, generation, addr)
}

func (p *proxyServer) Stop() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stopLocked()
}

func (p *proxyServer) stopLocked() {
	if p.cancel != nil {
		p.cancel()
		p.cancel = nil
	}
	if p.listener != nil {
		_ = p.listener.Close()
		p.listener = nil
	}
	for client := range p.clients {
		_ = client.Close()
	}
	p.addr = ""
}

func (p *proxyServer) serve(ctx context.Context, generation uint64, addr string) {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		if ctx.Err() == nil {
			p.l.Error("Failed to start proxy listener", "listen", addr, "error", err)
		}
		return
	}

	p.mu.Lock()
	if generation != p.generation || ctx.Err() != nil {
		p.mu.Unlock()
		_ = lis.Close()
		return
	}
	p.listener = lis
	p.mu.Unlock()

	p.l.Info("SOCKS5 proxy listening", "listen", addr)
	defer func() {
		_ = lis.Close()
		p.mu.Lock()
		if generation == p.generation && p.listener == lis {
			p.listener = nil
		}
		p.mu.Unlock()
	}()

	go func() {
		<-ctx.Done()
		_ = lis.Close()
	}()

	for {
		client, err := lis.Accept()
		if err != nil {
			if ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
				p.l.Error("Proxy listener stopped", "listen", addr, "error", err)
			}
			return
		}

		p.mu.Lock()
		if generation != p.generation || ctx.Err() != nil {
			p.mu.Unlock()
			_ = client.Close()
			return
		}
		p.clients[client] = struct{}{}
		p.mu.Unlock()

		go p.process(client)
	}
}

func (p *proxyServer) process(client net.Conn) {
	defer func() {
		p.mu.Lock()
		delete(p.clients, client)
		p.mu.Unlock()
		_ = client.Close()
	}()

	clientAddr := client.RemoteAddr().String()
	start := time.Now()
	_ = client.SetDeadline(time.Now().Add(proxyHandshakeTimeout))
	reader := bufio.NewReader(client)
	first, err := reader.Peek(1)
	if err != nil {
		p.l.Debug("Proxy detector failed", "client", clientAddr, "error", err)
		return
	}

	if first[0] == socks5Version {
		p.handleSOCKS5(clientAddr, start, reader, client)
		return
	}
	p.handleHTTP(clientAddr, start, reader, client)
}

func (p *proxyServer) handleSOCKS5(clientAddr string, start time.Time, reader *bufio.Reader, client net.Conn) {
	if err := socks5Auth(reader, client); err != nil {
		p.l.Debug("SOCKS5 authentication failed", "client", clientAddr, "error", err)
		return
	}

	target, targetAddr, err := socks5Connect(reader, client)
	if err != nil {
		p.l.Debug("SOCKS5 connect failed", "client", clientAddr, "error", err)
		return
	}
	defer target.Close()

	p.l.Info("SOCKS5 connection", "client", clientAddr, "target", targetAddr, "connect", time.Since(start))
	_ = client.SetDeadline(time.Time{})
	proxyForward(client, reader, target)
}

func (p *proxyServer) handleHTTP(clientAddr string, start time.Time, reader *bufio.Reader, client net.Conn) {
	req, err := http.ReadRequest(reader)
	if err != nil {
		p.l.Debug("HTTP proxy request failed", "client", clientAddr, "error", err)
		return
	}
	defer req.Body.Close()

	if req.Method == http.MethodConnect {
		target, err := net.DialTimeout("tcp", req.Host, proxyHandshakeTimeout)
		if err != nil {
			http.Error(&proxyResponseWriter{client}, err.Error(), http.StatusBadGateway)
			return
		}
		defer target.Close()

		_, _ = io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n")
		p.l.Info("HTTP proxy tunnel", "client", clientAddr, "target", req.Host, "connect", time.Since(start))
		_ = client.SetDeadline(time.Time{})
		proxyForward(client, reader, target)
		return
	}

	req.RequestURI = ""
	pruneHopHeaders(req.Header)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(&proxyResponseWriter{client}, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	p.l.Info("HTTP proxy request", "client", clientAddr, "target", req.Host, "connect", time.Since(start), "method", req.Method)
	_ = resp.Write(client)
}

func socks5Auth(reader io.Reader, client io.Writer) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		return fmt.Errorf("read greeting: %w", err)
	}
	if header[0] != socks5Version {
		return errors.New("invalid SOCKS version")
	}

	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(reader, methods); err != nil {
		return fmt.Errorf("read authentication methods: %w", err)
	}
	for _, method := range methods {
		if method == socks5NoAuthentication {
			_, err := client.Write([]byte{socks5Version, socks5NoAuthentication})
			return err
		}
	}

	_, _ = client.Write([]byte{socks5Version, 0xff})
	return errors.New("client does not support no-authentication SOCKS5")
}

func socks5Connect(reader io.Reader, client io.Writer) (net.Conn, string, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, "", fmt.Errorf("read request: %w", err)
	}
	if header[0] != socks5Version || header[1] != 1 {
		return nil, "", errors.New("only SOCKS5 CONNECT is supported")
	}

	var host string
	switch header[3] {
	case 1: // IPv4
		address := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(reader, address); err != nil {
			return nil, "", fmt.Errorf("read IPv4 address: %w", err)
		}
		host = net.IP(address).String()
	case 3: // Domain name
		var length [1]byte
		if _, err := io.ReadFull(reader, length[:]); err != nil {
			return nil, "", fmt.Errorf("read domain length: %w", err)
		}
		address := make([]byte, int(length[0]))
		if _, err := io.ReadFull(reader, address); err != nil {
			return nil, "", fmt.Errorf("read domain name: %w", err)
		}
		host = string(address)
	case 4: // IPv6
		address := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(reader, address); err != nil {
			return nil, "", fmt.Errorf("read IPv6 address: %w", err)
		}
		host = net.IP(address).String()
	default:
		return nil, "", errors.New("unsupported SOCKS5 address type")
	}

	var portBytes [2]byte
	if _, err := io.ReadFull(reader, portBytes[:]); err != nil {
		return nil, "", fmt.Errorf("read destination port: %w", err)
	}
	targetAddr := net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(portBytes[:]))))

	target, err := net.DialTimeout("tcp", targetAddr, proxyHandshakeTimeout)
	if err != nil {
		_, _ = client.Write([]byte{socks5Version, 0x05, 0, 1, 0, 0, 0, 0, 0, 0})
		return nil, "", fmt.Errorf("dial destination: %w", err)
	}

	if _, err := client.Write([]byte{socks5Version, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		target.Close()
		return nil, "", fmt.Errorf("write response: %w", err)
	}

	return target, targetAddr, nil
}

func proxyForward(client net.Conn, clientReader io.Reader, target net.Conn) {
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(target, clientReader)
		_ = target.Close()
		close(done)
	}()

	_, _ = io.Copy(client, target)
	_ = client.Close()
	<-done
}

type proxyResponseWriter struct{ net.Conn }

func (proxyResponseWriter) Header() http.Header { return make(http.Header) }

func (w *proxyResponseWriter) WriteHeader(statusCode int) {
	_, _ = fmt.Fprintf(w.Conn, "HTTP/1.1 %d %s\r\n\r\n", statusCode, http.StatusText(statusCode))
}

// pruneHopHeaders removes hop-by-hop headers before forwarding an HTTP request.
func pruneHopHeaders(h http.Header) {
	if connection := h.Get("Connection"); connection != "" {
		for _, field := range strings.Split(connection, ",") {
			if field = strings.TrimSpace(field); field != "" {
				h.Del(field)
			}
		}
	}

	for _, header := range []string{
		"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
		"Te", "Trailers", "Transfer-Encoding", "Upgrade",
	} {
		if header == "Te" && strings.EqualFold(h.Get(header), "trailers") {
			continue
		}
		h.Del(header)
	}
}
