package engine

import "testing"

func TestDetectNetInfoDefaultIf(t *testing.T) {
	ni := DetectNetInfo()
	t.Logf("%+v", ni)
	if ni.DefaultIf == "" {
		t.Skip("no default route in this environment")
	}
}
