package drain_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/InteractionLabs/traversal-connector/connector-lib/drain"
)

func TestZeroValueIsIdle(t *testing.T) {
	var tr drain.Tracker
	if err := tr.Wait(context.Background()); err != nil || tr.InFlight() != 0 || tr.Draining() {
		t.Fatalf("zero Tracker: %v, %d in flight, draining %v", err, tr.InFlight(), tr.Draining())
	}
}

func TestLimit(t *testing.T) {
	var tr drain.Tracker
	first, second, third := tr.Add(2), tr.Add(2), tr.Add(2)
	if !first || !second || third {
		t.Fatal("limit 2 did not admit exactly two")
	}
	tr.Done()
	if !tr.Add(2) || tr.InFlight() != 2 {
		t.Fatalf("after Done: %d in flight", tr.InFlight())
	}
	if !tr.Add(0) || tr.InFlight() != 3 {
		t.Fatal("limit 0 is no limit")
	}
}

// TestWait: Wait returns once the last Done lands, and only then.
func TestWait(t *testing.T) {
	var tr drain.Tracker
	tr.Add(0)
	tr.Add(0)
	done := make(chan error, 1)
	go func() { done <- tr.Wait(context.Background()) }()
	tr.Done()
	select {
	case err := <-done:
		t.Fatalf("Wait returned with one in flight: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	tr.Done()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Wait did not return once idle")
	}
}

// TestWaitDeadline: a done context ends Wait with how many remain.
func TestWaitDeadline(t *testing.T) {
	var tr drain.Tracker
	tr.Add(0)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := tr.Wait(ctx); !errors.Is(err, context.DeadlineExceeded) ||
		err.Error() != "1 still in flight: context deadline exceeded" {
		t.Fatalf("Wait = %v", err)
	}
}

// TestWaitSeesLateWork: work that starts while Wait waits, after the count
// first reaches zero, is waited for if it starts before Wait looks again.
func TestWaitSeesLateWork(t *testing.T) {
	var tr drain.Tracker
	for range 100 {
		tr.Add(0)
		var wg sync.WaitGroup
		wg.Go(func() { tr.Done(); tr.Add(0); tr.Done() })
		if err := tr.Wait(context.Background()); err != nil {
			t.Fatal(err)
		}
		wg.Wait()
		if n := tr.InFlight(); n != 0 {
			t.Fatalf("%d in flight", n)
		}
	}
}

func TestDraining(t *testing.T) {
	var tr drain.Tracker
	tr.Drain()
	if !tr.Draining() || !tr.Add(0) {
		t.Fatal("Draining is a flag; Add still admits")
	}
}

func TestDoneWithoutAdd(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("Done without Add did not panic")
		}
	}()
	var tr drain.Tracker
	tr.Done()
}
