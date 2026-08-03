package nebula

import (
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"

	"github.com/slackhq/nebula/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSOCKS5Connect(t *testing.T) {
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer targetListener.Close()

	go func() {
		conn, err := targetListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, len("through socks"))
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		_, _ = conn.Write(buf)
	}()

	client, server := net.Pipe()
	defer client.Close()
	p := newProxyServer(slog.New(slog.DiscardHandler))
	go p.process(server)

	_, err = client.Write([]byte{5, 1, 0})
	require.NoError(t, err)
	response := make([]byte, 2)
	_, err = io.ReadFull(client, response)
	require.NoError(t, err)
	assert.Equal(t, []byte{5, 0}, response)

	targetAddr := targetListener.Addr().(*net.TCPAddr)
	request := []byte{5, 1, 0, 1}
	request = append(request, targetAddr.IP.To4()...)
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, uint16(targetAddr.Port))
	request = append(request, port...)
	_, err = client.Write(request)
	require.NoError(t, err)

	response = make([]byte, 10)
	_, err = io.ReadFull(client, response)
	require.NoError(t, err)
	assert.Equal(t, byte(0), response[1])

	_, err = client.Write([]byte("through socks"))
	require.NoError(t, err)
	payload := make([]byte, len("through socks"))
	_, err = io.ReadFull(client, payload)
	require.NoError(t, err)
	assert.Equal(t, "through socks", string(payload))
}

func TestSOCKS5RejectsUnsupportedAuthentication(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	done := make(chan error, 1)
	go func() { done <- socks5Auth(server, server) }()

	_, err := client.Write([]byte{5, 1, 2})
	require.NoError(t, err)
	response := make([]byte, 2)
	_, err = io.ReadFull(client, response)
	require.NoError(t, err)
	assert.Equal(t, []byte{5, 0xff}, response)
	assert.Error(t, <-done)
}

func TestProxyAddress(t *testing.T) {
	c := config.NewC(slog.New(slog.DiscardHandler))
	c.Settings = map[string]any{"socks5": map[string]any{"port": 1080}}

	addr, enabled, err := proxyAddress(netip.MustParseAddr("192.168.100.10"), c)
	require.NoError(t, err)
	assert.True(t, enabled)
	assert.Equal(t, "192.168.100.10:1080", addr)

	c.Settings = map[string]any{"socks5": map[string]any{"port": 65536}}
	_, _, err = proxyAddress(netip.MustParseAddr("192.168.100.10"), c)
	assert.Error(t, err)

	c.Settings = map[string]any{"socks5": map[string]any{"port": "not-a-port"}}
	_, _, err = proxyAddress(netip.MustParseAddr("192.168.100.10"), c)
	assert.Error(t, err)
}
