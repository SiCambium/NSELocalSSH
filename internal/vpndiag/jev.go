package vpndiag

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Jev returns calibrated probabilities rather than free text: each question
// comes back as a number in [0,1], so there is nothing to parse out of prose and
// nothing to hallucinate. One call carries every node of a playbook, because the
// questions are non-conditional — all of them are evaluated against the same
// state — and the traversal then happens locally in Walk.

// Defaults. The model is pinned deliberately: a different model would answer
// the same criteria differently and silently change diagnoses.
const (
	DefaultBaseURL = "https://openrouter.ai/api/alpha"
	DefaultModel   = "typesafe/jev-1.13"
	DefaultTimeout = 45 * time.Second
)

// Question is one noul question.
type Question struct {
	Type         string            `json:"type"`
	Instructions string            `json:"instructions"`
	Criteria     map[string]string `json:"criteria"`
}

// Answer is one node's reply. Noul is a pointer because "not answered" and
// "answered 0.0" are different facts: the first cannot be branched on
// confidently, the second is a confident no. Collapsing them loses the
// distinction that drives the escalate flag.
type Answer struct {
	Type string   `json:"type"`
	Noul *float64 `json:"noul"`
}

// Usage is what the call cost. Jev bills on input tokens only.
type Usage struct {
	InputTokens int     `json:"input_tokens"`
	Cost        float64 `json:"cost"`
}

// ErrNotConfigured is returned when no API key is available. Callers treat it
// as "show the evidence without a verdict", not as a failure.
var ErrNotConfigured = errors.New("no OpenRouter API key configured")

// Client talks to the decisions endpoint.
//
// The key is a field, never read from the environment by this package: that
// keeps the package testable and means it has no way to reach a credential the
// caller did not deliberately hand it.
type Client struct {
	APIKey  string
	BaseURL string
	Model   string
	HTTP    *http.Client
}

// Configured reports whether a decision can be requested at all.
func (c *Client) Configured() bool { return c != nil && strings.TrimSpace(c.APIKey) != "" }

// DecideResponse is the parsed reply.
type DecideResponse struct {
	Answers map[string]Answer `json:"answers"`
	Usage   Usage             `json:"usage"`
}

type decideRequest struct {
	Model     string              `json:"model"`
	State     map[string]string   `json:"state"`
	Questions map[string]Question `json:"questions"`
}

// Decide asks every question against one state in a single round trip.
//
// Errors are deliberately plain and never include the key or the Authorization
// header. A caller is expected to degrade to showing the evidence rather than
// failing the whole operation — the walk is advisory, the evidence is not.
func (c *Client) Decide(ctx context.Context, state string, questions map[string]Question) (*DecideResponse, error) {
	if !c.Configured() {
		return nil, ErrNotConfigured
	}
	if len(questions) == 0 {
		return nil, errors.New("no questions to ask")
	}

	base := strings.TrimRight(orDefault(c.BaseURL, DefaultBaseURL), "/")
	body, err := json.Marshal(decideRequest{
		Model:     orDefault(c.Model, DefaultModel),
		State:     map[string]string{"case_evidence": state},
		Questions: questions,
	})
	if err != nil {
		return nil, fmt.Errorf("encoding request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/decisions", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")

	httpc := c.HTTP
	if httpc == nil {
		httpc = &http.Client{Timeout: DefaultTimeout}
	}
	resp, err := httpc.Do(req)
	if err != nil {
		// Deliberately does not wrap err: a transport error can carry the full
		// request URL, and this string reaches the UI.
		return nil, errors.New("could not reach the decision service")
	}
	defer resp.Body.Close()

	// Capped: an error page should not be echoed wholesale into an API response.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, errors.New("could not read the decision service response")
	}

	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return nil, errors.New("the decision service rejected the API key (401) — check or rotate it")
	case resp.StatusCode == http.StatusTooManyRequests:
		return nil, errors.New("the decision service is rate limiting this key (429)")
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("the decision service returned %d: %s", resp.StatusCode, firstLine(raw, 200))
	}

	var out DecideResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, errors.New("the decision service returned a response that could not be parsed")
	}
	if out.Answers == nil {
		return nil, errors.New("the decision service response carried no answers")
	}
	// A question answered out of range would branch on nonsense, so drop it and
	// let Walk treat it as unanswered — which flags low confidence rather than
	// inventing a decision.
	for id, a := range out.Answers {
		if a.Noul != nil && (*a.Noul < 0 || *a.Noul > 1) {
			out.Answers[id] = Answer{Type: a.Type}
		}
	}
	return &out, nil
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

func firstLine(b []byte, max int) string {
	s := strings.TrimSpace(string(b))
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > max {
		s = s[:max] + "…"
	}
	return s
}
