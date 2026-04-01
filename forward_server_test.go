package nebula

import (
	"net/netip"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/stretchr/testify/require"
)

func TestGetForwardMappingSupportsStringMaps(t *testing.T) {
	c := config.NewC(logrus.New())
	err := c.LoadString(`
forward:
  - port: 2222
    targets:
      - "192.168.77.3:22"
  - port: 8006
    targets:
      - "192.168.77.75:8006"
`)
	require.NoError(t, err)

	vpnNet := netip.MustParsePrefix("10.10.10.1/24")
	got := getForwardMapping(logrus.New(), vpnNet, c)

	require.Len(t, got, 2)
	require.Equal(t, "10.10.10.1:2222", got[0].addr)
	require.Equal(t, []string{"192.168.77.3:22"}, got[0].targets)
	require.Equal(t, "10.10.10.1:8006", got[1].addr)
	require.Equal(t, []string{"192.168.77.75:8006"}, got[1].targets)
}
