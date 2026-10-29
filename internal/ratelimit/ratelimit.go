// Package ratelimit provides a per-key token-bucket rate limiter.
package ratelimit

import (
	"sync"
	"time"
)

type bucket struct {
	tokens float64
	last   time.Time
}

// Limiter allows `rate` requests per second per key, with bursts up to `burst`.
type Limiter struct {
	mu      sync.Mutex
	rate    float64
	burst   float64
	buckets map[string]*bucket
	now     func() time.Time
}

// New returns a Limiter. A rate of 0 disables limiting.
func New(rate float64, burst int) *Limiter {
	return &Limiter{rate: rate, burst: float64(burst), buckets: map[string]*bucket{}, now: time.Now}
}

// Allow reports whether one more request from key may proceed.
func (l *Limiter) Allow(key string) bool {
	if l.rate <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
