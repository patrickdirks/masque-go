package masque

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"

	"github.com/dunglas/httpsfv"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

const requestProtocol = "connect-udp"

var capsuleProtocolHeaderValue string

func init() {
	v, err := httpsfv.Marshal(httpsfv.NewItem(true))
	if err != nil {
		panic(fmt.Sprintf("failed to marshal capsule protocol header value: %v", err))
	}
	capsuleProtocolHeaderValue = v
}

// Request is the parsed CONNECT-UDP request returned from ParseRequest.
// Target is the target server that the client requests to connect to.
// It can either be DNS name:port or an IP:port.
type Request struct {
	Target string
	Host   string
}

// RequestParseError is returned from ParseRequest if parsing the CONNECT-UDP request fails.
// It is recommended that the request is rejected with the corresponding HTTP status code.
type RequestParseError struct {
	HTTPStatus int
	Err        error
}

func (e *RequestParseError) Error() string { return e.Err.Error() }
func (e *RequestParseError) Unwrap() error { return e.Err }

// ParseRequest parses a CONNECT-UDP request.
// The template is the URI template that clients will use to configure this UDP proxy.
func ParseRequest(r *http.Request, template *uritemplate.Template) (*Request, error) {
	req, _, err := ParseRequestECN(r, template)
	return req, err

}

func ParseRequestECN(r *http.Request, template *uritemplate.Template) (*Request, ECNState, error) {
	u, err := url.Parse(template.Raw())
	if err != nil {
		return nil, ECNState{}, &RequestParseError{
			HTTPStatus: http.StatusInternalServerError,
			Err:        fmt.Errorf("failed to parse template: %w", err),
		}
	}

	if r.Method != http.MethodConnect {
		return nil, ECNState{}, &RequestParseError{
			HTTPStatus: http.StatusMethodNotAllowed,
			Err:        fmt.Errorf("expected CONNECT request, got %s", r.Method),
		}
	}
	if r.Proto != requestProtocol {
		return nil, ECNState{}, &RequestParseError{
			HTTPStatus: http.StatusNotImplemented,
			Err:        fmt.Errorf("unexpected protocol: %s", r.Proto),
		}
	}
	if r.Host != u.Host {
		return nil, ECNState{}, &RequestParseError{
			HTTPStatus: http.StatusBadRequest,
			Err:        fmt.Errorf("host in :authority (%s) does not match template host (%s)", r.Host, u.Host),
		}
	}

	// The capsule protocol header is optional, but if it's present,
	// we need to validate its value.
	capsuleHeaderValues, ok := r.Header[http3.CapsuleProtocolHeader]
	if ok {
		item, err := httpsfv.UnmarshalItem(capsuleHeaderValues)
		if err != nil {
			return nil, ECNState{}, &RequestParseError{
				HTTPStatus: http.StatusBadRequest,
				Err:        fmt.Errorf("invalid capsule header value: %s", capsuleHeaderValues),
			}
		}
		if v, ok := item.Value.(bool); !ok {
			return nil, ECNState{}, &RequestParseError{
				HTTPStatus: http.StatusBadRequest,
				Err:        fmt.Errorf("incorrect capsule header value type: %s", reflect.TypeOf(item.Value)),
			}
		} else if !v {
			return nil, ECNState{}, &RequestParseError{
				HTTPStatus: http.StatusBadRequest,
				Err:        fmt.Errorf("incorrect capsule header value: %t", item.Value),
			}
		}
	}

	match := template.Match(r.URL.String())
	targetHost := unescape(match.Get(uriTemplateTargetHost).String())
	targetPortStr := match.Get(uriTemplateTargetPort).String()
	if targetHost == "" || targetPortStr == "" {
		return nil, ECNState{}, &RequestParseError{
			HTTPStatus: http.StatusBadRequest,
			Err:        fmt.Errorf("expected target_host and target_port"),
		}
	}
	// IPv6 addresses need to be enclosed in [], otherwise resolving the address will fail.
	if strings.Contains(targetHost, ":") {
		targetHost = "[" + targetHost + "]"
	}
	targetPort, err := strconv.Atoi(targetPortStr)
	if err != nil {
		return nil, ECNState{}, &RequestParseError{
			HTTPStatus: http.StatusBadRequest,
			Err:        fmt.Errorf("failed to decode target_port: %w", err),
		}
	}
	var ecnConfig ECNState
	if ecnBody := r.Header.Get("Proxy-ECN"); ecnBody != "" {
		var err error
		if ecnConfig, err = ParseProxyECN(ecnBody); err != nil {
			// Currently we throw an error if ECNHeader invalid -> Soft-Fail might be better
			return nil, ECNState{}, &RequestParseError{
				HTTPStatus: http.StatusBadRequest,
				Err:        fmt.Errorf("invalid Proxy-ECN header: %w", err),
			}
		}
	}

	return &Request{
		Target: fmt.Sprintf("%s:%d", targetHost, targetPort),
		Host:   r.Host,
	}, ecnConfig, nil
}

func escape(s string) string   { return strings.ReplaceAll(s, ":", "%3A") }
func unescape(s string) string { return strings.ReplaceAll(s, "%3A", ":") }

// ParseProxyECN parses the "Proxy-ECN" header string.
func ParseProxyECN(headerValue string) (ECNState, error) {
	state := ECNState{}

	//Validate
	if headerValue == "" {
		return state, nil // Not present means disabled
	}

	parts := strings.Split(headerValue, ";")
	if len(parts) == 0 {
		return state, nil
	}

	// ECN enabled
	firstPart := strings.TrimSpace(parts[0])
	switch firstPart {
	case "?0":
		state.Enabled = false
		return state, nil
	case "?1":
		state.Enabled = true
	default:
		return state, errors.New("masque: Proxy-ECN header must start with ?0 or ?1")
	}

	// Parse Parameters
	for _, part := range parts[1:] {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Split key=value
		key, valStr, found := strings.Cut(part, "=")
		if !found {
			continue
		}

		// Parse the integer value
		val, err := strconv.ParseUint(valStr, 10, 64)
		if err != nil {
			return state, fmt.Errorf("masque: invalid ECN ID for %s: %w", key, err)
		}

		// Map to struct fields
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "ect0":
			state.ContextIdECT0 = val
		case "ect1":
			state.ContextIdECT1 = val
		case "ce":
			state.ContextIdCE = val
		}
	}

	// Validate that we received all IDs + valid mapping
	if state.Enabled {
		if state.ContextIdECT0 == 0 || state.ContextIdECT1 == 0 || state.ContextIdCE == 0 {
			return state, errors.New("masque: incomplete ECN parameters provided")
		}
		if state.ContextIdECT0%2 != 0 {
			return state, errors.New("masque: ContextID for ECT0 must be even")
		}
		if state.ContextIdECT1%2 != 0 {
			return state, errors.New("masque: ContextID for ECT1 must be even")
		}
		if state.ContextIdCE%2 != 0 {
			return state, errors.New("masque: ContextID for CE must be even")
		}
		if state.ContextIdECT0 == state.ContextIdECT1 {
			return state, errors.New("masque: ContectID for ECT1 and ECT0 cannot be the same")
		}
		if state.ContextIdECT0 == state.ContextIdCE {
			return state, errors.New("masque: ContectID for ECT0 and CE cannot be the same")
		}
		if state.ContextIdCE == state.ContextIdECT1 {
			return state, errors.New("masque: ContectID for ECT1 and CE cannot be the same")
		}

	}

	return state, nil
}
