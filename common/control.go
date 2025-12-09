package common

import "encoding/json"

// ControlRequest is sent by client over TLS control channel to request a session.
// ClientName should match the client certificate CN.
type ControlRequest struct {
	ClientName string `json:"client_name"`
}

// ControlResponse returns session parameters and a base64-encoded session key.
type ControlResponse struct {
	SessionID  uint32 `json:"session_id"`
	SessionKey string `json:"session_key"`
	UDPPort    int    `json:"udp_port"`
	ClientIP   string `json:"client_ip"`
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
