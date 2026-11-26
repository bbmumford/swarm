// Copyright (c) 2026 Brandon Miller-Mumford.
// Licensed under the MIT License; see LICENSE.

package swarm

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

// TestStopDuringStartDoesNotRace stops nodes while their Start is still
// setting up. Under the race detector a Stop whose wg.Wait ran beside Start's
// wg.Add for the ticker was reported as a data race; Start must also return
// once the node is stopped.
func TestStopDuringStartDoesNotRace(t *testing.T) {
	for i := 0; i < 200; i++ {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		n, err := New(Config{PrivKey: priv, TrustCheck: acceptAllRecords})
		if err != nil {
			t.Fatal(err)
		}
		if err := Wire(n, newMemNet().attach(n.(*nodeImpl).id)); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- n.Start(ctx) }()
		_ = n.Stop()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			cancel()
			t.Fatalf("run %d: Start did not return after Stop", i)
		}
		cancel()
	}
}

// TestStopInsideStartsWindowReturnsStart lands Stop exactly between Start's
// first stopped check and its lock: Start must see the node stopped and
// return ErrStopped, not store a cancel Stop has already passed by and block
// until its caller's context ends.
func TestStopInsideStartsWindowReturnsStart(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	n, err := New(Config{PrivKey: priv, TrustCheck: acceptAllRecords})
	if err != nil {
		t.Fatal(err)
	}
	impl := n.(*nodeImpl)
	if err := Wire(n, newMemNet().attach(impl.id)); err != nil {
		t.Fatal(err)
	}
	impl.beforeStartLock = func() { _ = n.Stop() }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- n.Start(ctx) }()
	select {
	case err := <-done:
		if err != ErrStopped {
			t.Fatalf("Start after a Stop inside its window returned %v, want ErrStopped", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after a Stop inside its window")
	}
}
