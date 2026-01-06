package common

import "encoding/json"

// ControlRequest is sent by client over TLS control channel to request a session.
// ClientName should match the client certificate CN.
type ControlRequest struct {
	ClientName string `json:"client_name"`
}

// ControlResponse returns session parameters for the QUIC data plane.
type ControlResponse struct {
	SessionID  uint32 `json:"session_id"`
	DataPort   int    `json:"data_port"`
	ClientIP   string `json:"client_ip"`
	ClientIPv6 string `json:"client_ip6,omitempty"`
}

func (r ControlRequest) Marshal() ([]byte, error) {
	return json.Marshal(r)
}

func (r *ControlRequest) Unmarshal(b []byte) error {
	return json.Unmarshal(b, r)
}

func (r ControlResponse) Marshal() ([]byte, error) {
	return json.Marshal(r)
}

func (r *ControlResponse) Unmarshal(b []byte) error {
	return json.Unmarshal(b, r)
}
