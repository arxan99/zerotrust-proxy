package proxy

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arxan99/zerotrust-proxy/internal/auth"
	"github.com/arxan99/zerotrust-proxy/internal/policy"
	"github.com/arxan99/zerotrust-proxy/internal/ratelimit"
)

// syncBuffer is a goroutine-safe log sink: the proxy writes the access log
// after the response is sent, so tests read it concurrently.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) lines() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := strings.TrimSpace(b.buf.String())
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func setup(t *testing.T, rate float64) (*Server, *syncBuffer, *httptest.Server) {
	t.Helper()
	eng, err := policy.New(policy.Config{
		Categories: map[string][]string{"malware": {"evil.test"}},
		Groups: map[string]policy.Group{
			"engineering": {DefaultAction: policy.Block, Rules: []policy.Rule{
				{Name: "block-malware", Action: policy.Block, Categories: []string{"malware"}},
				{Name: "allow-local", Action: policy.Allow, Domains: []string{"127.0.0.1"}},
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	users := auth.NewStore(map[string]auth.User{
		"alice": {Salt: "x", Hash: auth.HashPassword("x", "pw"), Group: "engineering"},
	})
	logs := &syncBuffer{}
	s := New(eng, users, ratelimit.New(rate, 2), logs)
	return s, logs, httptest.NewServer(s)
}

func proxyClient(p *httptest.Server, user, pass string) *http.Client {
	u, _ := url.Parse(p.URL)
	if user != "" {
		u.User = url.UserPassword(user, pass)
	}
	return &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(u)}}
}

// lastLog waits for the n-th log line and returns it.
func lastLog(t *testing.T, buf *syncBuffer, n int) LogEntry {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	lines := buf.lines()
	for len(lines) < n && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
		lines = buf.lines()
	}
	if len(lines) < n {
		t.Fatalf("want %d log lines, got %d", n, len(lines))
	}
	var e LogEntry
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &e); err != nil {
		t.Fatalf("bad log line: %v", err)
	}
	return e
}

func TestAllowedRequestIsForwardedAndLogged(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Error("credentials leaked to origin")
		}
		io.WriteString(w, "hello")
	}))
	defer origin.Close()
	_, logs, p := setup(t, 0)
	defer p.Close()

	resp, err := proxyClient(p, "alice", "pw").Get(origin.URL + "/index.html")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "hello" {
		t.Fatalf("got %d %q", resp.StatusCode, body)
	}
	e := lastLog(t, logs, 1)
	if e.User != "alice" || e.Action != "allow" || e.Rule != "allow-local" || e.Path != "/index.html" {
		t.Fatalf("unexpected log %+v", e)
	}
}

func TestMissingCredentials(t *testing.T) {
	_, logs, p := setup(t, 0)
	defer p.Close()
	resp, err := proxyClient(p, "", "").Get("http://127.0.0.1:1/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("want 407, got %d", resp.StatusCode)
	}
	if e := lastLog(t, logs, 1); e.Rule != "auth-failed" {
		t.Fatalf("unexpected log %+v", e)
	}
}

func TestBlockedByPolicy(t *testing.T) {
	_, logs, p := setup(t, 0)
	defer p.Close()
	resp, err := proxyClient(p, "alice", "pw").Get("http://evil.test/payload")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403, got %d", resp.StatusCode)
	}
	if e := lastLog(t, logs, 1); e.Rule != "block-malware" || e.Category != "malware" {
		t.Fatalf("unexpected log %+v", e)
	}
}

func TestRateLimit(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer origin.Close()
	_, _, p := setup(t, 0.001) // burst of 2, effectively no refill
	defer p.Close()
	c := proxyClient(p, "alice", "pw")
	codes := []int{}
	for i := 0; i < 3; i++ {
		resp, err := c.Get(origin.URL)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		codes = append(codes, resp.StatusCode)
	}
	if codes[2] != http.StatusTooManyRequests {
		t.Fatalf("third request should be limited, got %v", codes)
	}
}

func TestConnectTunnel(t *testing.T) {
	// A raw TCP echo server stands in for an HTTPS origin.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		io.Copy(c, c)
		c.Close()
	}()
	_, logs, p := setup(t, 0)
	defer p.Close()

	conn, err := net.Dial("tcp", strings.TrimPrefix(p.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cred := base64.StdEncoding.EncodeToString([]byte("alice:pw"))
	io.WriteString(conn, "CONNECT "+ln.Addr().String()+" HTTP/1.1\r\nHost: "+ln.Addr().String()+
		"\r\nProxy-Authorization: Basic "+cred+"\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("CONNECT failed: %v %v", err, resp)
	}
	io.WriteString(conn, "ping")
	got := make([]byte, 4)
	if _, err := io.ReadFull(br, got); err != nil || string(got) != "ping" {
		t.Fatalf("tunnel echo failed: %v %q", err, got)
	}
	conn.(*net.TCPConn).CloseWrite()
	io.Copy(io.Discard, br)
	if e := lastLog(t, logs, 1); e.Method != "CONNECT" || e.Action != "allow" {
		t.Fatalf("unexpected log %+v", e)
	}
}
