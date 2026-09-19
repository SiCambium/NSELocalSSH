package nse

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

var promptBytes = regexp.MustCompile(`[A-Za-z0-9._-]+\([^)]*\)#\s*$`)

// topPromptBytes matches only the bare top-level prompt (no sub-context
// suffix like "-eth-1"), used to detect when a multi-line config session
// has fully unwound back to the root.
var topPromptBytes = regexp.MustCompile(`[A-Za-z0-9._-]+\(config\)#\s*$`)

// cliErrorLineRE matches the error conventions observed live on this CLI:
// "%Error processing cli command", "Invalid arguments", and the bare
// "Error <...>" form that the DHCP pool context uses (CONFIRMED on NSE
// 4000 firmware 2.3: "Error setting dhcp pool parameters: The input mac
// is already bound"). That third form has no "%" prefix, so before it was
// listed here a rejected `bind` was classified OK and reported to the user
// as applied. There is no known success token, so success is still
// inferred as "no error line".
var cliErrorLineRE = regexp.MustCompile(`(?m)^\s*(%.*|Invalid .*|Error .*)\s*$`)

// LineResult is the outcome of sending one line within a RunSequence.
type LineResult struct {
	Line   string `json:"line"`
	Output string `json:"output"`
	OK     bool   `json:"ok"`
	Error  string `json:"error,omitempty"`
}

func classifyLine(cmd, raw string) LineResult {
	clean := stripCLI(raw, cmd)
	r := LineResult{Line: cmd, Output: clean}
	if m := cliErrorLineRE.FindString(clean); m != "" {
		r.Error = strings.TrimSpace(m)
		return r
	}
	r.OK = true
	return r
}

type Client struct {
	Cfg Config

	mu sync.Mutex
	// Set when a connect attempt fails, so the next one can fail fast
	// instead of spending the dial timeout again. Guarded by mu, like the
	// connection itself.
	lastConnErr error
	lastConnAt  time.Time
	conn        *ssh.Client
	session     *ssh.Session
	stdin       io.WriteCloser
	incoming    <-chan []byte

	// Per-device capability and cache state for FetchCloudConfig's
	// fallback path (see cloudconfig.go). Guarded by its own mutex rather
	// than mu, so it can be read and written around a Run call without
	// nesting locks.
	capMu           sync.Mutex
	noCloudJSON     bool
	cloudJSONMisses int
	derivedCfg      CloudConfig
	derivedCfgAt    time.Time
	derivedCfgOK    bool

	// Recorded command output for demo mode (see demo.go). Nil in normal
	// operation; non-nil means no SSH connection is ever opened. Guarded
	// by mu, like the session it stands in for.
	replay map[string]string
}

// cloudJSONMissLimit is how many non-definitive empty replies to
// `service show cloud-json-config` it takes before the client gives up on
// the command. See noteCloudJSONMiss.
const cloudJSONMissLimit = 2

// CloudJSONUnsupported reports whether this device has been written off as
// unable to answer `service show cloud-json-config`, in which case
// FetchCloudConfig stops paying for the round-trip and goes straight to
// its `show config` fallback.
func (c *Client) CloudJSONUnsupported() bool {
	c.capMu.Lock()
	defer c.capMu.Unlock()
	return c.noCloudJSON
}

// noteCloudJSONMiss records a reply to cloud-json-config that carried no
// JSON. A reply in the CLI's error convention ("%Error ...", "Invalid
// ...") is a definitive "no such command" and is believed at once.
// Anything else is not: a real NSE3000 running firmware 2.3-r6 answers
// "could not open file" — a plain, non-conventional line meaning the
// command exists but has no file to read — while a desynced session could
// return literally anything. Both look the same from here, so a
// non-definitive miss has to repeat before it counts, which bounds the
// wasted round-trips without letting one stale read permanently downgrade
// a device that does support the command.
func (c *Client) noteCloudJSONMiss(definitive bool) {
	c.capMu.Lock()
	defer c.capMu.Unlock()
	c.cloudJSONMisses++
	if definitive || c.cloudJSONMisses >= cloudJSONMissLimit {
		c.noCloudJSON = true
	}
}

// noteCloudJSONHit resets the miss counter after a good reply, so
// occasional failures spread over a long session never accumulate into a
// verdict.
func (c *Client) noteCloudJSONHit() {
	c.capMu.Lock()
	defer c.capMu.Unlock()
	c.cloudJSONMisses = 0
}

// cachedDerivedConfig returns a recently derived fallback CloudConfig, if
// one is still fresh. The fallback costs a full `show config` per call and
// a single Configuration page load fans out into several FetchCloudConfig
// calls, so a very short TTL collapses that burst without the UI ever
// showing a stale value: every write path clears the cache (see
// RunSequence) and nothing but a write changes what `show config` says.
func (c *Client) cachedDerivedConfig(ttl time.Duration) (CloudConfig, bool) {
	c.capMu.Lock()
	defer c.capMu.Unlock()
	if !c.derivedCfgOK || time.Since(c.derivedCfgAt) >= ttl {
		return CloudConfig{}, false
	}
	return c.derivedCfg, true
}

func (c *Client) storeDerivedConfig(cfg CloudConfig) {
	c.capMu.Lock()
	defer c.capMu.Unlock()
	c.derivedCfg = cfg
	c.derivedCfgAt = time.Now()
	c.derivedCfgOK = true
}

func (c *Client) invalidateDerivedConfig() {
	c.capMu.Lock()
	defer c.capMu.Unlock()
	c.derivedCfgOK = false
}

func NewClient(cfg Config) *Client {
	return &Client{Cfg: cfg}
}

// connectBackoff is how long a failed connect suppresses the next dial.
//
// Every read takes the client mutex and, on a disconnected client, dials
// before doing anything. Against an unreachable device each of those pays
// the full 12s dial timeout while holding the lock, and the dashboard's
// auto-refresh keeps queueing more — so anything else that needs the
// client waits behind the whole queue. Switching to another connection is
// exactly that: measured at 47s behind three queued polls, which reads as
// "it won't let me switch".
//
// Failing fast inside this window keeps the lock free, so a switch gets
// through promptly while the device is down.
const connectBackoff = 10 * time.Second

func (c *Client) connect() error {
	if c.lastConnErr != nil && time.Since(c.lastConnAt) < connectBackoff {
		return c.lastConnErr
	}
	c.closeLocked()
	config := &ssh.ClientConfig{
		User:            c.Cfg.User,
		Auth:            []ssh.AuthMethod{ssh.Password(c.Cfg.Password)},
		HostKeyCallback: TrustedHostKeyCallback(KnownHostsPath()),
		Timeout:         12 * time.Second,
	}
	conn, err := ssh.Dial("tcp", c.Cfg.Addr(), config)
	if err != nil {
		c.lastConnErr, c.lastConnAt = err, time.Now()
		return err
	}
	session, err := conn.NewSession()
	if err != nil {
		conn.Close()
		return err
	}
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := session.RequestPty("xterm", 50, 200, modes); err != nil {
		session.Close()
		conn.Close()
		return err
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		session.Close()
		conn.Close()
		return err
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		session.Close()
		conn.Close()
		return err
	}
	if err := session.Shell(); err != nil {
		session.Close()
		conn.Close()
		return err
	}
	ch := make(chan []byte, 32)
	go func() {
		buf := make([]byte, 8192)
		for {
			n, err := stdout.Read(buf)
			if n > 0 {
				b := make([]byte, n)
				copy(b, buf[:n])
				ch <- b
			}
			if err != nil {
				close(ch)
				return
			}
		}
	}()
	c.conn = conn
	c.session = session
	c.stdin = stdin
	c.incoming = ch
	if _, err := c.waitPrompt(15 * time.Second); err != nil {
		c.closeLocked()
		// A device that accepts TCP but never presents a prompt costs the
		// same lock time as an unreachable one, so it backs off too.
		c.lastConnErr, c.lastConnAt = err, time.Now()
		return err
	}
	c.lastConnErr = nil
	return nil
}

func (c *Client) waitPrompt(timeout time.Duration) (string, error) {
	deadline := time.After(timeout)
	var acc bytes.Buffer
	for {
		select {
		case <-deadline:
			tail := acc.String()
			if len(tail) > 200 {
				tail = tail[len(tail)-200:]
			}
			return acc.String(), fmt.Errorf("timed out waiting for NSE prompt: %s", tail)
		case chunk, ok := <-c.incoming:
			if !ok {
				return acc.String(), fmt.Errorf("ssh session closed")
			}
			acc.Write(chunk)
			b := acc.Bytes()
			if bytes.Contains(b[max(0, len(b)-80):], []byte("--More--")) || bytes.Contains(b[max(0, len(b)-80):], []byte("--more--")) {
				_, _ = c.stdin.Write([]byte(" "))
			}
			if promptBytes.Find(b) != nil {
				return acc.String(), nil
			}
		}
	}
}

func (c *Client) ensure() error {
	if c.conn != nil && c.session != nil && c.incoming != nil {
		return nil
	}
	return c.connect()
}

// ErrCLILineBreak marks a command rejected for spanning lines. It is a
// bad request, not a device failure, so the API layer can answer 400
// rather than reporting it as a gateway error.
var ErrCLILineBreak = errors.New("refusing to send a CLI command containing a line break")

// validateCLILine rejects a command that would not stay on its own line.
// runLocked terminates every command with a carriage return, so an
// embedded CR or LF makes the remainder a second command of whoever
// supplied the value — and this app builds command lines by interpolating
// request text in dozens of places (a hostname, a RADIUS client's name, a
// secret, a DNS domain). Guarding each of those individually would only
// hold until the next one was written, so the check lives here, where
// every command without exception passes through.
//
// The offending line is quoted with %q so the newline cannot mangle the
// error itself, and redacted first if it carries a secret.
func validateCLILine(command string) error {
	if !strings.ContainsAny(command, "\r\n") {
		return nil
	}
	shown := command
	if secretLine(shown) {
		shown = redactSecretLine(shown)
	}
	if len(shown) > 80 {
		shown = shown[:80] + "…"
	}
	return fmt.Errorf("%w: the remainder would run as a separate command: %q", ErrCLILineBreak, shown)
}

func (c *Client) Run(command string, timeout time.Duration) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.runLocked(command, timeout)
}

func (c *Client) runLocked(command string, timeout time.Duration) (string, error) {
	if err := validateCLILine(command); err != nil {
		return "", err
	}
	if c.replay != nil {
		out, ok := c.replay[strings.TrimSpace(command)]
		if !ok {
			return "", fmt.Errorf("demo mode: no recorded output for %q", command)
		}
		return out, nil
	}
	if err := c.ensure(); err != nil {
		return "", err
	}
	if _, err := c.stdin.Write([]byte(command + "\r")); err != nil {
		if err2 := c.connect(); err2 != nil {
			return "", err
		}
		if _, err = c.stdin.Write([]byte(command + "\r")); err != nil {
			return "", err
		}
	}
	out, err := c.waitPrompt(timeout)
	if err != nil {
		c.closeLocked()
		return out, err
	}
	return out, nil
}

// RunSequence sends a sequence of CLI lines within a single locked session,
// e.g. entering a sub-context, setting several fields, and leaving it. The
// whole sequence — not each line individually — holds the client's lock,
// because the risk being defended against is a concurrent dashboard poll
// (Run calls on a timer) injecting a "show ..." command in the middle of a
// sub-context and corrupting which prompt we're in, not concurrent writers
// racing each other.
//
// If stopOnError is true, the sequence stops at the first line whose
// output matches the CLI's error convention. Either way, RunSequence always
// attempts to return the session to the top-level prompt before releasing
// the lock (see unwindLocked).
func (c *Client) RunSequence(lines []string, timeout time.Duration, stopOnError bool) ([]LineResult, error) {
	// Validated before anything is sent: a line break anywhere in the
	// batch must not leave half of it applied.
	for _, line := range lines {
		if err := validateCLILine(line); err != nil {
			return nil, err
		}
	}
	// Every config write goes through here, and any of them can change
	// what `show config` says — drop the fallback CloudConfig cache so the
	// next read re-derives it.
	c.invalidateDerivedConfig()
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensure(); err != nil {
		return nil, err
	}
	var results []LineResult
	var lastOut string
	for _, line := range lines {
		out, err := c.runLocked(line, timeout)
		if err != nil {
			// runLocked already closed the connection on transport failure;
			// there is no session left to unwind.
			results = append(results, LineResult{Line: line, Error: err.Error()})
			return results, err
		}
		lastOut = out
		r := classifyLine(line, out)
		results = append(results, r)
		if !r.OK && stopOnError {
			break
		}
	}
	if len(results) > 0 {
		c.unwindLocked(lastOut, timeout)
	}
	return results, nil
}

// unwindLocked returns the session to the top-level "(config)#" prompt
// after a RunSequence, sending "exit" only while lastOut shows we're still
// inside a sub-context (never blindly, since sending "exit" from the top
// level is untested and could itself error). If it can't unwind within a
// handful of attempts, the shared shell is dropped entirely rather than
// left wedged mid-context — the next ensure() reconnects cleanly, since
// SSH login is known to land directly at "(config)#".
func (c *Client) unwindLocked(lastOut string, timeout time.Duration) {
	out := lastOut
	for i := 0; i < 8; i++ {
		if topPromptBytes.MatchString(out) {
			return
		}
		next, err := c.runLocked("exit", timeout)
		if err != nil {
			return
		}
		out = next
	}
	c.closeLocked()
}

// LocalAddr reports the address this session reaches the device from, as
// the device sees it — the local end of the live SSH connection.
//
// It exists so a source restriction cannot be set to a range that
// excludes the session setting it. Any NAT between here and the device
// would make this the pre-NAT address and the check unreliable, but on
// the LAN path this app is built for, it is the address the device
// applies its device-access rules against.
func (c *Client) LocalAddr() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensure(); err != nil || c.conn == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(c.conn.LocalAddr().String())
	if err != nil {
		return ""
	}
	return host
}

func (c *Client) Snapshot() Config {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Cfg
}

func (c *Client) ApplyConfig(cfg Config) error {
	// A different device (profile switch) may well support
	// cloud-json-config even if this one didn't, and its config is
	// certainly not the one we cached.
	c.capMu.Lock()
	c.noCloudJSON = false
	c.cloudJSONMisses = 0
	c.derivedCfgOK = false
	c.capMu.Unlock()

	c.mu.Lock()
	defer c.mu.Unlock()
	c.Cfg = cfg
	c.lastConnErr, c.lastConnAt = nil, time.Time{}
	c.closeLocked()
	if cfg.Password == "" {
		return fmt.Errorf("password is empty")
	}
	return c.connect()
}

func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeLocked()
}

func (c *Client) closeLocked() {
	if c.session != nil {
		_ = c.session.Close()
	}
	if c.conn != nil {
		_ = c.conn.Close()
	}
	c.session = nil
	c.conn = nil
	c.stdin = nil
	c.incoming = nil
}

// SetPasswordInPlace changes the credential this client will authenticate
// with on its *next* connection, without disturbing the session it
// already holds.
//
// This exists for one caller: changing the device's admin password.
// ApplyConfig would reconnect, which is exactly wrong there — the open
// session is the one sending the change, and it stays authenticated
// because SSH authenticates at connect time. What must move to the new
// credential is the fresh login SafeApplier makes to prove the device is
// still reachable, and that reads Cfg at dial time.
//
// Without this, a successful password change looks like a lockout: the
// probe dials with the credential the change just invalidated, fails, and
// the change is undone.
func (c *Client) SetPasswordInPlace(password string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Cfg.Password = password
}
