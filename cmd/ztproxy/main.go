// Command ztproxy runs the zero-trust forward proxy.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/arxan99/zerotrust-proxy/internal/auth"
	"github.com/arxan99/zerotrust-proxy/internal/policy"
	"github.com/arxan99/zerotrust-proxy/internal/proxy"
	"github.com/arxan99/zerotrust-proxy/internal/ratelimit"
)

func main() {
	listen := flag.String("listen", ":8080", "proxy listen address")
	admin := flag.String("admin", "127.0.0.1:9090", "metrics/health listen address")
	policyFile := flag.String("policy", "configs/policy.json", "policy file")
	usersFile := flag.String("users", "configs/users.json", "users file")
	logFile := flag.String("log", "", "access log file (default: stdout)")
	rate := flag.Float64("rate", 20, "requests per second per user (0 disables)")
	burst := flag.Int("burst", 40, "burst size per user")
	hashPw := flag.String("hash", "", "print a salt and hash for this password, then exit")
	flag.Parse()

	if *hashPw != "" {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			log.Fatal(err)
		}
		salt := hex.EncodeToString(b)
		fmt.Printf(`{"salt": %q, "hash": %q}`+"\n", salt, auth.HashPassword(salt, *hashPw))
		return
	}

	eng, err := policy.Load(*policyFile)
	if err != nil {
		log.Fatal(err)
	}
	users, err := auth.Load(*usersFile)
	if err != nil {
		log.Fatal(err)
	}
	var out io.Writer = os.Stdout
	if *logFile != "" {
		f, err := os.OpenFile(*logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		out = f
	}

	srv := proxy.New(eng, users, ratelimit.New(*rate, *burst), out)

	mux := http.NewServeMux()
	mux.Handle("/metrics", srv.MetricsHandler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok\n") })

	proxyServer := &http.Server{Addr: *listen, Handler: srv, ReadHeaderTimeout: 10 * time.Second}
	adminServer := &http.Server{Addr: *admin, Handler: mux, ReadHeaderTimeout: 5 * time.Second}

	go func() {
		log.Printf("admin listening on %s", *admin)
		if err := adminServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()
	go func() {
		log.Printf("proxy listening on %s", *listen)
		if err := proxyServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Print("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	proxyServer.Shutdown(ctx)
	adminServer.Shutdown(ctx)
}
