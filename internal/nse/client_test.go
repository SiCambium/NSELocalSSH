package nse

import "testing"

func TestClassifyLineOK(t *testing.T) {
	raw := "wan-name wan1\r\nNSE-Caravan(config-eth-1)# "
	r := classifyLine("wan-name wan1", raw)
	if !r.OK || r.Error != "" {
		t.Fatalf("classifyLine() = %+v, want OK", r)
	}
}

func TestClassifyLineError(t *testing.T) {
	raw := "bogus-command\r\n%Error processing cli command\r\nNSE-Caravan(config)# "
	r := classifyLine("bogus-command", raw)
	if r.OK {
		t.Fatalf("classifyLine() = %+v, want error", r)
	}
	if r.Error == "" {
		t.Fatal("expected non-empty Error")
	}
}

func TestClassifyLineInvalidArguments(t *testing.T) {
	raw := "?\r\nInvalid arguments\r\nNSE-Caravan(config)# "
	r := classifyLine("?", raw)
	if r.OK {
		t.Fatalf("classifyLine() = %+v, want error", r)
	}
}

func TestTopPromptBytesDistinguishesSubContext(t *testing.T) {
	if !topPromptBytes.MatchString("NSE-Caravan(config)# ") {
		t.Fatal("expected top prompt to match")
	}
	if topPromptBytes.MatchString("NSE-Caravan(config-eth-1)# ") {
		t.Fatal("sub-context prompt must not match topPromptBytes")
	}
	if !promptBytes.MatchString("NSE-Caravan(config-eth-1)# ") {
		t.Fatal("promptBytes should still match sub-context prompts")
	}
}
