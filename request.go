package masque

import (
	"context"
	"fmt"
	"net"
	"net/http"

	"github.com/dunglas/httpsfv"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

const (
	requestProtocol       = "connect-udp"
	uriTemplateTargetHost = "target_host"
	uriTemplateTargetPort = "target_port"
)

var capsuleProtocolHeaderValue string

func init() {
	v, err := httpsfv.Marshal(httpsfv.NewItem(true))
	if err != nil {
		panic(fmt.Sprintf("failed to marshal capsule protocol header value: %v", err))
	}
	capsuleProtocolHeaderValue = v
}

// Request is a CONNECT-UDP request created by NewRequest.
// The zero value is not valid.
type Request struct {
	req    *http.Request
	target string
	ecn    ECNState
}

// NewRequest creates a CONNECT-UDP request for the given target.
// The target must be given as a host:port.
func NewRequest(ctx context.Context, proxyTemplate *uritemplate.Template, target string) (*Request, error) {
	return NewRequestECN(ctx, proxyTemplate, target, ECNState{})
}

// NewRequestECN creates a CONNECT-UDP request for the given target.
// If ecnConfig is enabled, the Context IDs are announced to the proxy in the Proxy-ECN header.
func NewRequestECN(ctx context.Context, proxyTemplate *uritemplate.Template, target string, ecnConfig ECNState) (*Request, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("masque: failed to parse target: %w", err)
	}
	str, err := proxyTemplate.Expand(uritemplate.Values{
		uriTemplateTargetHost: uritemplate.String(host),
		uriTemplateTargetPort: uritemplate.String(port),
	})
	if err != nil {
		return nil, fmt.Errorf("masque: failed to expand Template: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, str, nil)
	if err != nil {
		return nil, fmt.Errorf("masque: failed to create request: %w", err)
	}
	req.Proto = requestProtocol
	req.Host = req.URL.Host
	req.Header.Set(http3.CapsuleProtocolHeader, capsuleProtocolHeaderValue)
	if ecnConfig.Enabled {
		ecnHeaderValue := fmt.Sprintf("?1; ect1=%d; ect0=%d; ce=%d", ecnConfig.ContextIdECT1, ecnConfig.ContextIdECT0, ecnConfig.ContextIdCE)
		req.Header.Set("Proxy-ECN", ecnHeaderValue)
	}
	return &Request{req: req, target: target, ecn: ecnConfig}, nil
}

// Header returns the HTTP header fields sent with the CONNECT-UDP request.
// Callers may add custom headers before dialing.
func (r *Request) Header() http.Header { return r.req.Header }
