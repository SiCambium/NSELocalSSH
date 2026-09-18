package nse

import (
	"strings"
	"testing"
	"time"
)

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

// TestValidateCLILineRejectsInjection covers the guard that makes a
// command stay on its own line. runLocked terminates every command with a
// carriage return, so a value carrying its own CR or LF would run the
// remainder as a second command — on a firewall.
func TestValidateCLILineRejectsInjection(t *testing.T) {
	for _, bad := range []string{
		"tailscale auth-key tskey-abc\rno management ssh",
		"tailscale auth-key tskey-abc\nno management ssh",
		"hostname branch\r\nno management ssh",
		"secret abc\rno management https",
		"name Leeds\nshutdown",
	} {
		err := validateCLILine(bad)
		if err == nil {
			t.Errorf("validateCLILine(%q) = nil — this would reach the device as two commands", bad)
			continue
		}
		// The error must not carry the secret it was protecting, and must
		// not itself span lines.
		if strings.Contains(err.Error(), "tskey-abc") || strings.Contains(err.Error(), "secret abc") {
			t.Errorf("error leaks the value it rejected: %v", err)
		}
		if strings.ContainsAny(err.Error(), "\r\n") {
			t.Errorf("error message itself spans lines: %q", err.Error())
		}
	}

	for _, ok := range []string{
		"show config",
		"tailscale auth-key tskey-legitimate",
		"hostname Leeds-branch",
		"load-balance monitor-hosts 8.8.8.8,1.1.1.1",
		"",
	} {
		if err := validateCLILine(ok); err != nil {
			t.Errorf("validateCLILine(%q) = %v, want nil", ok, err)
		}
	}
}

// TestRunSequenceRejectsBatchBeforeSending checks that a bad line stops
// the whole batch rather than leaving the lines before it applied. The
// client has no connection here, so reaching the device at all would
// surface as a dial error instead.
func TestRunSequenceRejectsBatchBeforeSending(t *testing.T) {
	c := NewClient(Config{Host: "127.0.0.1", Port: "1", User: "x", Password: "y"})
	_, err := c.RunSequence([]string{
		"interface eth 1",
		"wan-name wan1\rno management ssh",
		"exit",
	}, time.Second, true)
	if err == nil {
		t.Fatal("a batch containing a line break must be refused")
	}
	if !strings.Contains(err.Error(), "line break") {
		t.Errorf("error = %v, want the line-break refusal (not a connection error)", err)
	}
}
