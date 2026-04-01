package nebula

import (
	"io"
	"math/rand"
	"net"
	"net/netip"
	"reflect"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
)

type fwd struct {
	addr    string   // listening port
	targets []string // forward target
}

var forwardServers []*ForwardServer
var forwardMapping []*fwd

func forwardMain(l *logrus.Logger, vpnNet netip.Prefix, c *config.C) func() {
	c.RegisterReloadCallback(func(c *config.C) {
		reloadForward(l, vpnNet, c)
	})

	return func() {
		startForward(l, vpnNet, c)
	}
}

func reloadForward(l *logrus.Logger, vpnNet netip.Prefix, c *config.C) {
	if reflect.DeepEqual(forwardMapping, getForwardMapping(l, vpnNet, c)) {
		l.Debug("No Forward server config change detected")
		return
	}

	l.Debug("Restarting Forward server")
	for _, s := range forwardServers {
		s.Shutdown()
	}
	forwardServers = nil
	go startForward(l, vpnNet, c)
}

func newFwd(vpnNet netip.Prefix, cfg any) *fwd {
	var (
		portValue   any
		address     string
		addressSeen bool
		targetValue any
	)

	switch m := cfg.(type) {
	case map[string]any:
		portValue = m["port"]
		targetValue = m["targets"]
		address, addressSeen = m["address"].(string)
	case map[interface{}]interface{}:
		portValue = m["port"]
		targetValue = m["targets"]
		address, addressSeen = m["address"].(string)
	default:
		return nil
	}

	port, ok := toInt(portValue)
	if !ok {
		return nil
	}
	targets, ok := toStringSlice(targetValue)
	if !ok {
		return nil
	}

	if !addressSeen {
		address = vpnNet.Addr().String()
	}

	return &fwd{
		addr:    address + ":" + strconv.Itoa(port),
		targets: targets,
	}
}

func getForwardMapping(l *logrus.Logger, vpnNet netip.Prefix, c *config.C) (fwds []*fwd) {
	f := c.Get("forward")
	switch f := f.(type) {
	case map[string]any:
		if fwd := newFwd(vpnNet, f); fwd != nil {
			fwds = append(fwds, fwd)
		}
	case map[interface{}]interface{}:
		if fwd := newFwd(vpnNet, f); fwd != nil {
			fwds = append(fwds, fwd)
		}
	case []any:
		for _, v := range f {
			if fwd := newFwd(vpnNet, v); fwd != nil {
				fwds = append(fwds, fwd)
			}
		}
	}
	return
}

func startForward(l *logrus.Logger, vpnNet netip.Prefix, c *config.C) {
	f := c.Get("forward")
	if f == nil {
		return
	}

	rand.Seed(time.Now().UnixNano())

	forwardMapping = getForwardMapping(l, vpnNet, c)
	if len(forwardMapping) == 0 {
		l.WithField("config", f).Error("Bad forward config")
	}

	for _, fwd := range forwardMapping {
		forwardServer := &ForwardServer{Addr: fwd.addr, logger: l, Targets: fwd.targets}
		l.WithFields(logrus.Fields{
			"forwardListener": fwd.addr,
			"targets":         fwd.targets,
		}).Infof("Starting Forward server")

		forwardServers = append(forwardServers, forwardServer)
		go func() {
			err := forwardServer.ListenAndServe()
			defer forwardServer.Shutdown()
			if err != nil {
				l.Errorf("Failed to start Forward server: %s\n ", err.Error())
			}
		}()
	}
}

// ForwardSerer redirects connection to remote targets
type ForwardServer struct {
	Addr    string
	logger  *logrus.Logger
	lis     net.Listener
	Targets []string
}

func (s *ForwardServer) ListenAndServe() (err error) {
	s.lis, err = net.Listen("tcp", s.Addr)
	if err != nil {
		return
	}

	for {
		client, err := s.lis.Accept()
		if err != nil {
			s.logger.Debugf("forward accept failed: %v", err)
			continue
		}
		go s.process(client)
	}
}

func (s *ForwardServer) Shutdown() {
	if s.lis != nil {
		s.lis.Close()
	}
}

func (s *ForwardServer) ShuffledTargets() []string {
	targets := make([]string, len(s.Targets))
	copy(targets, s.Targets)
	rand.Shuffle(len(targets), func(i, j int) {
		targets[i], targets[j] = targets[j], targets[i]
	})
	return targets
}

func (s *ForwardServer) process(client net.Conn) {
	clientAddr := client.RemoteAddr().String()
	forwarded := false
	start := time.Now()
	for i, target := range s.ShuffledTargets() {
		conn, err := net.Dial("tcp", target)
		if err == nil {
			forwarded = true
			tcpForward(client, conn)
			s.logger.WithField("index", i).
				WithField("remote", clientAddr).
				WithField("target", target).
				WithField("connect", time.Since(start)).
				Infof("Forward")
			break
		} else {
			s.logger.WithField("client", clientAddr).WithField("target", target).Errorf("Forward failed: %v", err)
		}
	}
	if !forwarded {
		client.Close()
	}
}

func tcpForward(client, target net.Conn) {
	forward := func(src, dest net.Conn) {
		defer src.Close()
		defer dest.Close()
		io.Copy(src, dest)
	}
	go forward(client, target)
	go forward(target, client)
}

func toInt(v any) (int, bool) {
	switch i := v.(type) {
	case int:
		return i, true
	case int64:
		return int(i), true
	case uint64:
		return int(i), true
	case float64:
		return int(i), true
	default:
		return 0, false
	}
}

func toStringSlice(v any) ([]string, bool) {
	switch targets := v.(type) {
	case []string:
		return targets, true
	case []any:
		out := make([]string, 0, len(targets))
		for _, target := range targets {
			s, ok := target.(string)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	default:
		return nil, false
	}
}
