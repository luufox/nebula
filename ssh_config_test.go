package nebula

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateSSHListen(t *testing.T) {
	pki := &PKI{}
	pki.cs.Store(&CertState{myVpnAddrs: []netip.Addr{
		netip.MustParseAddr("192.168.100.10"),
		netip.MustParseAddr("fd00::10"),
	}})

	tests := []struct {
		name    string
		listen  string
		wantErr bool
	}{
		{name: "Nebula IPv4 on port 22", listen: "192.168.100.10:22"},
		{name: "Nebula IPv6 on port 22", listen: "[fd00::10]:22"},
		{name: "different local address on port 22", listen: "127.0.0.1:22", wantErr: true},
		{name: "wildcard address on port 22", listen: "0.0.0.0:22", wantErr: true},
		{name: "unprivileged port", listen: "127.0.0.1:2222"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSSHListen(tt.listen, pki)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}

}
