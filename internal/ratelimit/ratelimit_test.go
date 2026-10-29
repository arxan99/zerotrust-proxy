package ratelimit

import (
	"testing"
	"time"
)

func TestTokenBucket(t *testing.T) {
	now := time.Unix(0, 0)
	l := New(1, 3) // 1 req/s, burst 3
	l.now = func() time.Time { return now }

	for i := 0; i < 3; i++ {
		if !l.Allow("alice") {
			t.Fatalf("request %d should pass within burst", i)
		}
	}
	if l.Allow("alice") {
		t.Fatal("4th request should be limited")
	}
	if !l.Allow("bob") {
		t.Fatal("other users have their own bucket")
	}
	now = now.Add(time.Second)
	if !l.Allow("alice") {
		t.Fatal("bucket should refill after 1s")
	}
}

func TestDisabled(t *testing.T) {
	l := New(0, 0)
	for i := 0; i < 100; i++ {
		if !l.Allow("x") {
			t.Fatal("rate 0 should disable limiting")
		}
	}
}
