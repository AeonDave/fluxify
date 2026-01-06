package common

import "testing"

func TestControlRequestRoundtrip(t *testing.T) {
	req := ControlRequest{ClientName: "alice"}
	b, err := req.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out ControlRequest
	if err := out.Unmarshal(b); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.ClientName != req.ClientName {
		t.Fatalf("mismatch: %s vs %s", out.ClientName, req.ClientName)
	}
}

func TestControlResponseRoundtrip(t *testing.T) {
	resp := ControlResponse{SessionID: 7, DataPort: 9000, ClientIP: "10.0.0.2"}
	b, err := resp.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out ControlResponse
	if err := out.Unmarshal(b); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out != resp {
		t.Fatalf("mismatch: %+v vs %+v", out, resp)
	}
}
