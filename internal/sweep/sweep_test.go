package sweep

import (
	"bytes"
	"context"
	"log"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/CarriedWorldUniverse/interchange/internal/storage"
)

func newStore(t *testing.T) *storage.SQLite {
	t.Helper()
	s, err := storage.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.CreateSchema(context.Background()); err != nil {
		t.Fatalf("schema: %v", err)
	}
	return s
}

func TestOnceEvictsOldEnvelopes(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	now := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)

	// Two envelopes: one 8 days old (should evict at 7-day cutoff), one
	// 1 day old (should survive).
	old := storage.Envelope{
		MsgID: "old", PathID: "p", Direction: storage.AToB,
		ReceivedAt: now.Add(-8 * 24 * time.Hour),
		Ciphertext: "c", Signature: "s", OuterJSON: "{}",
	}
	fresh := storage.Envelope{
		MsgID: "fresh", PathID: "p", Direction: storage.AToB,
		ReceivedAt: now.Add(-24 * time.Hour),
		Ciphertext: "c", Signature: "s", OuterJSON: "{}",
	}
	_ = s.InsertEnvelope(ctx, old)
	_ = s.InsertEnvelope(ctx, fresh)

	var logBuf bytes.Buffer
	sw := New(s, Config{
		Clock:  func() time.Time { return now },
		Logger: log.New(&logBuf, "", 0),
	})

	sw.Once(ctx)

	remaining, _ := s.ListEnvelopes(ctx, "p", storage.AToB, "")
	if len(remaining) != 1 || remaining[0].MsgID != "fresh" {
		t.Errorf("after sweep: %+v", remaining)
	}
	if !strings.Contains(logBuf.String(), "evicted 1") {
		t.Errorf("log missing eviction count: %q", logBuf.String())
	}
}

func TestOnceExpiresPendingRequests(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	now := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)

	_ = s.InsertPairRequest(ctx, storage.PairRequest{
		RequestID: "old-pending", Status: storage.StatusPending,
		CreatedAt: now.Add(-48 * time.Hour),
		ExpiresAt: now.Add(-1 * time.Hour),
		RequesterJSON: "{}", TargetNexusID: "owner",
	})
	_ = s.InsertPairRequest(ctx, storage.PairRequest{
		RequestID: "fresh-pending", Status: storage.StatusPending,
		CreatedAt: now,
		ExpiresAt: now.Add(24 * time.Hour),
		RequesterJSON: "{}", TargetNexusID: "owner",
	})

	sw := New(s, Config{Clock: func() time.Time { return now }, Logger: log.New(&bytes.Buffer{}, "", 0)})
	sw.Once(ctx)

	r, _ := s.GetPairRequest(ctx, "old-pending")
	if r.Status != storage.StatusExpired {
		t.Errorf("old-pending status = %q, want expired", r.Status)
	}
	r, _ = s.GetPairRequest(ctx, "fresh-pending")
	if r.Status != storage.StatusPending {
		t.Errorf("fresh-pending got touched: %q", r.Status)
	}
}

// TestOnceIsSilentWhenNothingToDo — no log line when both counts are
// zero. Matters because at steady state the sweep runs every hour and
// filling logs with "evicted 0" noise defeats the purpose of logging.
func TestOnceIsSilentWhenNothingToDo(t *testing.T) {
	s := newStore(t)
	var logBuf bytes.Buffer
	sw := New(s, Config{Logger: log.New(&logBuf, "", 0)})
	sw.Once(context.Background())
	if logBuf.Len() != 0 {
		t.Errorf("sweep logged with nothing to do: %q", logBuf.String())
	}
}

// TestRunFiresOnTicker — shortens the interval and waits for two sweeps.
// counter wraps Once via a stub storage so we can count calls.
func TestRunFiresOnTicker(t *testing.T) {
	counter := &countingStore{inner: newStore(t)}
	sw := New(counter, Config{
		Interval: 10 * time.Millisecond,
		Logger:   log.New(&bytes.Buffer{}, "", 0),
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- sw.Run(ctx) }()

	// Wait for at least 3 sweeps (30ms) then cancel.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned %v, want nil on cancel", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not return after ctx cancel")
	}

	if atomic.LoadInt32(&counter.deleteEnvelopesCalls) < 2 {
		t.Errorf("DeleteEnvelopesOlderThan called %d times, expected at least 2",
			atomic.LoadInt32(&counter.deleteEnvelopesCalls))
	}
	if atomic.LoadInt32(&counter.expireRequestsCalls) < 2 {
		t.Errorf("ExpirePendingRequests called %d times, expected at least 2",
			atomic.LoadInt32(&counter.expireRequestsCalls))
	}
}

// TestRunNoSweepBeforeFirstTick pins the behavior that Run waits for
// the interval before the first sweep — startup should be boring, not
// racing against other init.
func TestRunNoSweepBeforeFirstTick(t *testing.T) {
	counter := &countingStore{inner: newStore(t)}
	sw := New(counter, Config{
		Interval: 500 * time.Millisecond, // long enough that we cancel first
		Logger:   log.New(&bytes.Buffer{}, "", 0),
	})

	ctx, cancel := context.WithCancel(context.Background())
	go sw.Run(ctx)
	time.Sleep(50 * time.Millisecond)
	cancel()

	if atomic.LoadInt32(&counter.deleteEnvelopesCalls) != 0 {
		t.Errorf("sweep fired before first tick: %d calls",
			atomic.LoadInt32(&counter.deleteEnvelopesCalls))
	}
}

// TestConfigDefaults pins the fallback values. Changing any of these
// is a protocol-adjacent decision (7-day retention is in the spec).
func TestConfigDefaults(t *testing.T) {
	var c Config
	c.defaults()
	if c.Interval != time.Hour {
		t.Errorf("Interval default = %v, want 1h", c.Interval)
	}
	if c.EnvelopeMaxAge != 7*24*time.Hour {
		t.Errorf("EnvelopeMaxAge default = %v, want 7d", c.EnvelopeMaxAge)
	}
	if c.Clock == nil {
		t.Errorf("Clock default nil")
	}
	if c.Logger == nil {
		t.Errorf("Logger default nil")
	}
}

// countingStore wraps a real SQLite with atomic counters so we can
// observe how many times the sweeper touched the store across a ticker
// loop.
type countingStore struct {
	inner                *storage.SQLite
	deleteEnvelopesCalls int32
	expireRequestsCalls  int32
}

func (c *countingStore) DeleteEnvelopesOlderThan(ctx context.Context, cutoff time.Time) (int, error) {
	atomic.AddInt32(&c.deleteEnvelopesCalls, 1)
	return c.inner.DeleteEnvelopesOlderThan(ctx, cutoff)
}

func (c *countingStore) ExpirePendingRequests(ctx context.Context, cutoff time.Time) (int, error) {
	atomic.AddInt32(&c.expireRequestsCalls, 1)
	return c.inner.ExpirePendingRequests(ctx, cutoff)
}

// Remaining Storage methods delegate straight through.
func (c *countingStore) CreateSchema(ctx context.Context) error { return c.inner.CreateSchema(ctx) }
func (c *countingStore) InsertEnvelope(ctx context.Context, e storage.Envelope) error {
	return c.inner.InsertEnvelope(ctx, e)
}
func (c *countingStore) ListEnvelopes(ctx context.Context, p string, d storage.Direction, s string) ([]storage.Envelope, error) {
	return c.inner.ListEnvelopes(ctx, p, d, s)
}
func (c *countingStore) DeleteEnvelopesByMsgID(ctx context.Context, p string, ids []string) (int, error) {
	return c.inner.DeleteEnvelopesByMsgID(ctx, p, ids)
}
func (c *countingStore) InsertPairRequest(ctx context.Context, r storage.PairRequest) error {
	return c.inner.InsertPairRequest(ctx, r)
}
func (c *countingStore) GetPairRequest(ctx context.Context, id string) (storage.PairRequest, error) {
	return c.inner.GetPairRequest(ctx, id)
}
func (c *countingStore) ListPendingPairRequests(ctx context.Context) ([]storage.PairRequest, error) {
	return c.inner.ListPendingPairRequests(ctx)
}
func (c *countingStore) UpdatePairRequestStatus(ctx context.Context, id string, to storage.PairRequestStatus, o, p string) error {
	return c.inner.UpdatePairRequestStatus(ctx, id, to, o, p)
}
func (c *countingStore) InsertPair(ctx context.Context, p storage.Pair) error {
	return c.inner.InsertPair(ctx, p)
}
func (c *countingStore) GetPair(ctx context.Context, p string) (storage.Pair, error) {
	return c.inner.GetPair(ctx, p)
}
func (c *countingStore) Close() error { return c.inner.Close() }

var _ storage.Storage = (*countingStore)(nil)
