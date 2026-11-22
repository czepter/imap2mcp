package imapx

import (
	"errors"
	"testing"
	"time"
)

func TestAuthGuardStrikesCooldownAndReset(t *testing.T) {
	now := time.Unix(1000, 0)
	g := NewAuthGuard(3, 30*time.Second, func() time.Time { return now })
	if err := g.admit(); err != nil {
		t.Fatal(err)
	}
	if g.reject() {
		t.Fatal("latched on strike 1")
	}
	if !errors.Is(g.admit(), ErrLoginDeferred) {
		t.Fatal("no cooldown after strike 1")
	}
	now = now.Add(31 * time.Second)
	if err := g.admit(); err != nil {
		t.Fatal(err)
	}
	g.ok() // successful login resets the strikes
	if err := g.admit(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if g.reject() {
			t.Fatalf("latched on strike %d after reset", i+1)
		}
		now = now.Add(5 * time.Minute)
	}
	if !g.reject() || !g.Latched() {
		t.Fatal("third strike must latch")
	}
	if !errors.Is(g.admit(), ErrAuth) {
		t.Fatal("latched guard must return ErrAuth")
	}
	g.Clear()
	if g.Latched() || g.admit() != nil {
		t.Fatal("Clear must reset")
	}
}

func TestAuthGuardBurstCountsOnce(t *testing.T) {
	now := time.Unix(1000, 0)
	g := NewAuthGuard(3, 30*time.Second, func() time.Time { return now })
	for i := 0; i < 5; i++ { // five parallel logins refused at once
		if g.reject() {
			t.Fatalf("burst latched at refusal %d", i+1)
		}
	}
	now = now.Add(31 * time.Second)
	if g.reject() {
		t.Fatal("second strike must not latch")
	}
	now = now.Add(3 * time.Minute)
	if !g.reject() {
		t.Fatal("third spaced strike must latch")
	}
}

func TestDeferredAndRefusedAreDistinct(t *testing.T) {
	if errors.Is(ErrLoginDeferred, ErrLoginRefused) || errors.Is(ErrLoginRefused, ErrLoginDeferred) {
		t.Fatal("sentinels must differ")
	}
	e := &loginRefused{code: "AUTHENTICATIONFAILED"}
	if !errors.Is(e, ErrLoginRefused) {
		t.Fatal("coded refusal must match ErrLoginRefused")
	}
}
