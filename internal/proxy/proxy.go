// Package proxy implements the forward proxy: it authenticates each request,
// asks the policy engine for a decision, enforces it, and writes one JSON
// access-log line per request.
package proxy

import (
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/arxan99/zerotrust-proxy/internal/auth"
	"github.com/arxan99/zerotrust-proxy/internal/policy"
	"github.com/arxan99/zerotrust-proxy/internal/ratelimit"
)

// LogEntry is one access-log record (JSON Lines).
type LogEntry struct {
	Time       string `json:"ts"`
	ClientIP   string `json:"client_ip"`
	User       string `json:"user"`
	Group      string `json:"group"`
	Method     string `json:"method"`
	Host       string `json:"host"`
	Path       string `json:"path"`
	Action     string `json:"action"`
	Rule       string `json:"rule"`
	Category   string `json:"category,omitempty"`
	Status     int    `json:"status"`
	BytesOut   int64  `json:"bytes_out"`
	DurationMS int64  `json:"duration_ms"`
}

// Metrics are simple counters exposed on the admin endpoint.
type Metrics struct {
	Requests    atomic.Int64
	Allowed     atomic.Int64
	Blocked     atomic.Int64
	AuthFailed  atomic.Int64
	RateLimited atomic.Int64
}

// Server is an http.Handler that acts as a forward proxy.
type Server struct {
	Policy  *policy.Engine
	Users   *auth.Store
	Limiter *ratelimit.Limiter
	Metrics *Metrics

	logMu  sync.Mutex
	logOut io.Writer

	transport http.RoundTripper
	dialer    net.Dialer
}

// New creates a proxy server that writes access logs to logOut.
func New(p *policy.Engine, u *auth.Store, l *ratelimit.Limiter, logOut io.Writer) *Server {
	return &Server{
		Policy:  p,
		Users:   u,
		Limiter: l,
		Metrics: &Metrics{},
		logOut:  logOut,
		transport: &http.Transport{
			Proxy:               nil, // never chain to another proxy implicitly
			MaxIdleConns:        100,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
		},
		dialer: net.Dialer{Timeout: 10 * time.Second},
	}
}

// Hop-by-hop headers must not be forwarded (RFC 7230 section 6.1).
var hopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	s.Metrics.Requests.Add(1)
	entry := LogEntry{
		Time:     start.UTC().Format(time.RFC3339),
		ClientIP: clientIP(r),
		Method:   r.Method,
		Host:     hostOnly(r.Host),
	}
	if r.Method != http.MethodConnect {
		entry.Host = hostOnly(r.URL.Host)
		entry.Path = r.URL.Path
	}
	defer func() {
		entry.DurationMS = time.Since(start).Milliseconds()
		s.writeLog(entry)
	}()

	// 1. Verify identity: every request must authenticate.
	user, group, err := s.Users.Authenticate(r.Header.Get("Proxy-Authorization"))
	if err != nil {
		s.Metrics.AuthFailed.Add(1)
		entry.Action, entry.Rule, entry.Status = "block", "auth-failed", http.StatusProxyAuthRequired
		w.Header().Set("Proxy-Authenticate", `Basic realm="ztproxy"`)
		http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
		return
	}
	entry.User, entry.Group = user, group

	// 2. Per-user rate limit.
	if !s.Limiter.Allow(user) {
		s.Metrics.RateLimited.Add(1)
		entry.Action, entry.Rule, entry.Status = "block", "rate-limited", http.StatusTooManyRequests
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	// 3. Policy decision.
	d := s.Policy.Evaluate(policy.Request{User: user, Group: group, Host: entry.Host, Path: entry.Path})
	entry.Action, entry.Rule, entry.Category = string(d.Action), d.Rule, d.Category
	if d.Action == policy.Block {
		s.Metrics.Blocked.Add(1)
		entry.Status = http.StatusForbidden
		http.Error(w, "blocked by policy: "+d.Rule, http.StatusForbidden)
		return
	}
	s.Metrics.Allowed.Add(1)

	// 4. Forward.
	if r.Method == http.MethodConnect {
		entry.Status, entry.BytesOut = s.tunnel(w, r)
		return
	}
	entry.Status, entry.BytesOut = s.forward(w, r)
}

// forward relays a plain HTTP request.
func (s *Server) forward(w http.ResponseWriter, r *http.Request) (int, int64) {
	if !r.URL.IsAbs() {
		http.Error(w, "absolute URL required", http.StatusBadRequest)
		return http.StatusBadRequest, 0
	}
	out := r.Clone(r.Context())
	out.RequestURI = ""
	removeHopHeaders(out.Header)

	resp, err := s.transport.RoundTrip(out)
	if err != nil {
		http.Error(w, "upstream error", http.StatusBadGateway)
		return http.StatusBadGateway, 0
	}
	defer resp.Body.Close()

	removeHopHeaders(resp.Header)
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	n, _ := io.Copy(w, resp.Body)
	return resp.StatusCode, n
}

// tunnel handles HTTPS via CONNECT. Traffic stays encrypted end to end; the
// policy decision is made on the destination hostname only.
func (s *Server) tunnel(w http.ResponseWriter, r *http.Request) (int, int64) {
	upstream, err := s.dialer.DialContext(r.Context(), "tcp", r.Host)
	if err != nil {
		http.Error(w, "upstream unreachable", http.StatusBadGateway)
		return http.StatusBadGateway, 0
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		upstream.Close()
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return http.StatusInternalServerError, 0
	}
	client, buf, err := hj.Hijack()
	if err != nil {
		upstream.Close()
		return http.StatusInternalServerError, 0
	}
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		client.Close()
		upstream.Close()
		return http.StatusOK, 0
	}

	var wg sync.WaitGroup
	var sent atomic.Int64
	wg.Add(2)
	go func() { // client -> upstream (include anything already buffered)
		defer wg.Done()
		if buf.Reader.Buffered() > 0 {
			io.CopyN(upstream, buf, int64(buf.Reader.Buffered()))
		}
		io.Copy(upstream, client)
		closeWrite(upstream)
	}()
	go func() { // upstream -> client
		defer wg.Done()
		n, _ := io.Copy(client, upstream)
		sent.Store(n)
		closeWrite(client)
	}()
	wg.Wait()
	client.Close()
	upstream.Close()
	return http.StatusOK, sent.Load()
}

func closeWrite(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		tc.CloseWrite()
	}
}

func (s *Server) writeLog(e LogEntry) {
	b, err := json.Marshal(e)
	if err != nil {
		log.Printf("log marshal: %v", err)
		return
	}
	s.logMu.Lock()
	defer s.logMu.Unlock()
	s.logOut.Write(append(b, '\n'))
}

// MetricsHandler serves counters in Prometheus text format.
func (s *Server) MetricsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		m := s.Metrics
		write := func(name string, v int64) {
			io.WriteString(w, "ztproxy_"+name+" "+itoa(v)+"\n")
		}
		write("requests_total", m.Requests.Load())
		write("allowed_total", m.Allowed.Load())
		write("blocked_total", m.Blocked.Load())
		write("auth_failed_total", m.AuthFailed.Load())
		write("rate_limited_total", m.RateLimited.Load())
	})
}

func removeHopHeaders(h http.Header) {
	for _, k := range h.Values("Connection") {
		for _, f := range strings.Split(k, ",") {
			h.Del(strings.TrimSpace(f))
		}
	}
	for _, k := range hopHeaders {
		h.Del(k)
	}
}

func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

func clientIP(r *http.Request) string {
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return h
	}
	return r.RemoteAddr
}

func itoa(v int64) string {
	b, _ := json.Marshal(v)
	return string(b)
}
