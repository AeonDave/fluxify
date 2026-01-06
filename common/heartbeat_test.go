package common

import "testing"

func TestHeartbeatPayloadRoundTrip(t *testing.T) {
	in := HeartbeatPayload{SendTime: 123456789}
	b := in.Marshal()
	var out HeartbeatPayload
	if err := out.Unmarshal(b); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.SendTime != in.SendTime {
		t.Fatalf("send time mismatch: %d vs %d", out.SendTime, in.SendTime)
	}
}
