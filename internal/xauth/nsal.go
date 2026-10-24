package xauth

import "net/http"

// nsalEndpoint is one NSAL endpoint entry.
type nsalEndpoint struct {
	Protocol             string `json:"Protocol"`
	Host                 string `json:"Host"`
	HostType             string `json:"HostType"`
	RelyingParty         string `json:"RelyingParty,omitempty"`
	SubRelyingParty      string `json:"SubRelyingParty,omitempty"`
	TokenType            string `json:"TokenType,omitempty"`
	SignaturePolicyIndex *int   `json:"SignaturePolicyIndex,omitempty"`
	Path                 string `json:"Path,omitempty"`
}

type signaturePolicy struct {
	Version             int      `json:"Version"`
	SupportedAlgorithms []string `json:"SupportedAlgorithms"`
	MaxBodyBytes        int      `json:"MaxBodyBytes"`
	ExtraHeaders        []string `json:"ExtraHeaders,omitempty"`
}

var zero = 0

// nsalEndpoints is the document xbl serves for both the default and the
// title NSAL. The relying parties are xbl's (every service here accepts the
// XSTS token xbl issued for them); the host list covers the names the
// supported titles call.
func nsalEndpoints() []nsalEndpoint {
	xbl := func(proto, host, kind string) nsalEndpoint {
		return nsalEndpoint{Protocol: proto, Host: host, HostType: kind, RelyingParty: "http://xboxlive.com", TokenType: "JWT", SignaturePolicyIndex: &zero}
	}
	eps := []nsalEndpoint{
		xbl("https", "xboxlive.com", "fqdn"),
		xbl("https", "*.xboxlive.com", "wildcard"),
		xbl("wss", "*.xboxlive.com", "wildcard"),
		{Protocol: "https", Host: "xsts.auth.xboxlive.com", HostType: "fqdn", RelyingParty: "http://auth.xboxlive.com", TokenType: "JWT", SignaturePolicyIndex: &zero},
		{Protocol: "https", Host: "api.minecraftservices.com", HostType: "fqdn", RelyingParty: "rp://api.minecraftservices.com/", TokenType: "JWT", SignaturePolicyIndex: &zero},
		{Protocol: "https", Host: "api-staging.minecraftservices.com", HostType: "fqdn", RelyingParty: "rp://api.minecraftservices.com/", TokenType: "JWT", SignaturePolicyIndex: &zero},
		{Protocol: "wss", Host: "signaling.minecraftservices.com", HostType: "fqdn", RelyingParty: "rp://api.minecraftservices.com/", TokenType: "JWT", SignaturePolicyIndex: &zero},
		{Protocol: "https", Host: "*.playfabapi.com", HostType: "wildcard", RelyingParty: "http://playfab.xboxlive.com/", TokenType: "JWT", SignaturePolicyIndex: &zero},
		{Protocol: "https", Host: "playfabapi.com", HostType: "fqdn", RelyingParty: "http://playfab.xboxlive.com/", TokenType: "JWT", SignaturePolicyIndex: &zero},
	}
	return eps
}

func (s *Service) nsal(w http.ResponseWriter, r *http.Request) {
	s.Log.Info("nsal", "path", r.URL.Path)
	writeJSON(w, http.StatusOK, map[string]any{
		"EndPoints": nsalEndpoints(),
		"SignaturePolicies": []signaturePolicy{{
			Version: 1, SupportedAlgorithms: []string{"ES256"}, MaxBodyBytes: 8192,
		}},
	})
}
