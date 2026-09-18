package nse

import (
	"bytes"
	"fmt"
	"io"
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

	mu       sync.Mutex
	conn     *ssh.Client
	session  *ssh.Session
	stdin    io.WriteCloser
	incoming <-chan []byte
}

func NewClient(cfg Config) *Client {
	return &Client{Cfg: cfg}
}

func (c *Client) connect() error {
	c.closeLocked()
	config := &ssh.ClientConfig{
		User:            c.Cfg.User,
		Auth:            []ssh.AuthMethod{ssh.Password(c.Cfg.Password)},
		HostKeyCallback: TrustedHostKeyCallback(KnownHostsPath()),
		Timeout:         12 * time.Second,
	}
	conn, err := ssh.Dial("tcp", c.Cfg.Addr(), config)
	if err != nil {
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
		return err
	}
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

func (c *Client) Run(command string, timeout time.Duration) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.runLocked(command, timeout)
}

func (c *Client) runLocked(command string, timeout time.Duration) (string, error) {
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

func (c *Client) Snapshot() Config {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Cfg
}

func (c *Client) ApplyConfig(cfg Config) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Cfg = cfg
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
