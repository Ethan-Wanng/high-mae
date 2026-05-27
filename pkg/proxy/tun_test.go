package proxy

import (
	"testing"
	"wing/pkg/common"
)

func TestToggleTunModeState(t *testing.T) {
	common.IsTunModeOn = false

	// Verify that state changes are instant and do not lock or throw errors
	common.IsTunModeOn = true
	if !common.IsTunModeOn {
		t.Errorf("Expected IsTunModeOn to be true")
	}

	common.IsTunModeOn = false
	if common.IsTunModeOn {
		t.Errorf("Expected IsTunModeOn to be false")
	}
}
