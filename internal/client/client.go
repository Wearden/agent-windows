package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/Wearden/agent-windows/internal/scanner"
	"github.com/Wearden/proto/wire"
)

type Client struct {
	base string
	http *http.Client
}

func New(base string) (*Client, error) {
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("server must be an HTTPS origin")
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || ip == nil || !ip.IsLoopback() {
			return nil, errors.New("HTTPS required except literal loopback IP")
		}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &Client{strings.TrimSuffix(u.String(), "/"), &http.Client{Timeout: 30 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirects refused") }}}, nil
}

func (c *Client) request(ctx context.Context, method, path, token string, in any, limit int64, statuses ...int) ([]byte, error) {
	if token == "" || len(token) > 512 || strings.ContainsAny(token, "\r\n") {
		return nil, errors.New("invalid bearer token")
	}
	var body []byte
	var err error
	if in != nil {
		body, err = json.Marshal(in)
		if err != nil {
			return nil, err
		}
		if len(body) > 8<<20 {
			return nil, errors.New("request exceeds 8 MiB")
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("cannot create API request")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, errors.New("agent API request failed")
	}
	defer resp.Body.Close()
	accepted := false
	for _, status := range statuses {
		if status == resp.StatusCode {
			accepted = true
		}
	}
	if !accepted {
		return nil, fmt.Errorf("agent API returned status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, errors.New("cannot read API response")
	}
	if int64(len(data)) > limit {
		return nil, errors.New("API response exceeds size limit")
	}
	return data, nil
}

func decode(data []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return errors.New("invalid API JSON response")
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return errors.New("trailing API response data")
	}
	return nil
}

func (c *Client) Enroll(ctx context.Context, token string, request wire.Enrollment) (wire.EnrollmentResponse, error) {
	var result wire.EnrollmentResponse
	if request.Version != wire.Version || request.OS != "windows" || !regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(request.RequestID) {
		return result, errors.New("enrollment requires a privately persisted request identity")
	}
	data, err := c.request(ctx, "POST", "/api/agent/v1/enroll", token, request, 4096, 201)
	if err != nil {
		return result, err
	}
	if err = decode(data, &result); err != nil {
		return result, err
	}
	if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`).MatchString(result.AgentID) || len(result.AgentToken) == 0 || len(result.AgentToken) > 512 || strings.ContainsAny(result.AgentToken, "\r\n") {
		return result, errors.New("invalid enrollment response")
	}
	return result, nil
}

func (c *Client) Heartbeat(ctx context.Context, token, id string) error {
	data, err := c.request(ctx, "POST", "/api/agent/v1/heartbeat", token, wire.Heartbeat{Version: wire.Version, AgentID: id, SentAt: time.Now().UTC()}, 1, 204)
	if err == nil && len(data) != 0 {
		return errors.New("heartbeat returned unexpected data")
	}
	return err
}

func (c *Client) Assignment(ctx context.Context, token string) (wire.Config, scanner.Ruleset, error) {
	var cfg wire.Config
	var rs scanner.Ruleset
	data, err := c.request(ctx, "GET", "/api/agent/v1/config", token, nil, 16384, 200)
	if err != nil {
		return cfg, rs, err
	}
	if err = decode(data, &cfg); err != nil {
		return cfg, rs, err
	}
	if cfg.Version != wire.Version || cfg.IntervalSeconds < 60 || cfg.IntervalSeconds > 604800 || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(cfg.RulesetSHA256) {
		return cfg, rs, errors.New("invalid assignment configuration")
	}
	data, err = c.request(ctx, "GET", "/api/agent/v1/ruleset", token, nil, 4<<20, 200)
	if err != nil {
		return cfg, rs, err
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != cfg.RulesetSHA256 {
		return cfg, rs, errors.New("ruleset digest mismatch")
	}
	rs, err = scanner.Decode(data)
	if err != nil {
		return cfg, rs, err
	}
	if cfg.BenchmarkID != rs.BenchmarkID || cfg.RulesetVersion != rs.RulesetVersion {
		return cfg, rs, errors.New("ruleset does not match configuration")
	}
	return cfg, rs, nil
}

func (c *Client) Report(ctx context.Context, token string, report wire.Report) error {
	if err := report.Validate(); err != nil {
		return err
	}
	data, err := c.request(ctx, "POST", "/api/agent/v1/reports", token, report, 4096, 200, 201)
	if err != nil {
		return err
	}
	var receipt wire.Receipt
	if err = decode(data, &receipt); err != nil {
		return err
	}
	if !receipt.Accepted || receipt.ReportID != report.ReportID {
		return errors.New("server did not accept matching report")
	}
	return nil
}

func (c *Client) Task(ctx context.Context, token string) (*wire.Task, error) {
	data, err := c.request(ctx, "GET", "/api/agent/v1/tasks", token, nil, 65536, 200)
	if err != nil {
		return nil, err
	}
	var envelope wire.TaskEnvelope
	if err = decode(data, &envelope); err != nil {
		return nil, err
	}
	return envelope.Task, nil
}

func (c *Client) TaskResult(ctx context.Context, token string, result wire.TaskResult) error {
	if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`).MatchString(result.TaskID) {
		return errors.New("invalid task result ID")
	}
	data, err := c.request(ctx, "POST", "/api/agent/v1/tasks/"+url.PathEscape(result.TaskID)+"/results", token, result, 4096, 200)
	if err != nil {
		return err
	}
	var receipt wire.TaskReceipt
	if err = decode(data, &receipt); err != nil {
		return err
	}
	if !receipt.Accepted || receipt.TaskID != result.TaskID || receipt.Revision != result.Revision {
		return errors.New("server did not accept matching task result")
	}
	return nil
}
