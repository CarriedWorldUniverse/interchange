// Package sweep runs the interchange's background retention jobs:
//
//   - Envelope eviction: delete mailbox envelopes older than the
//     configured age (default 7 days — spec §Retention).
//   - Pair-request expiry: transition pending requests older than their
//     expires_at to StatusExpired so the dashboard stops surfacing
//     abandoned pairing asks (default TTL 24 hours — spec §Pairing).
//
// The sweeper is context-aware so a graceful shutdown cancels the
// ticker cleanly. At PoC scale the two sweeps share one goroutine; if
// volume grows, they can be split without changing the public API.
package sweep

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/CarriedWorldUniverse/interchange/internal/storage"
)

// Config parameterizes the sweeper. Zero values fall back to sensible
// defaults so main can install a sweeper with a one-liner.
type Config struct {
	// Interval between sweeps. Default: 1 hour. Tests inject shorter.
	Interval time.Duration
	// EnvelopeMaxAge — envelopes older than this are deleted. Default 7 days.
	EnvelopeMaxAge time.Duration
	// Logger receives one line per sweep reporting counts. If nil,
	// uses log.Default.
	Logger *log.Logger
	// Clock lets tests pin time. If nil, time.Now.
	Clock func() time.Time
}

func (c *Config) defaults() {
	if c.Interval <= 0 {
		c.Interval = time.Hour
	}
	if c.EnvelopeMaxAge <= 0 {
		c.EnvelopeMaxAge = 7 * 24 * time.Hour
	}
	if c.Logger == nil {
		c.Logger = log.Default()
	}
	if c.Clock == nil {
		c.Clock = time.Now
	}
}

// Sweeper runs the retention loop.
type Sweeper struct {
	store  storage.Storage
	config Config
}

// New builds a Sweeper. The Config is copied; later mutations don't
// affect the sweeper.
func New(store storage.Storage, cfg Config) *Sweeper {
	cfg.defaults()
	return &Sweeper{store: store, config: cfg}
}

// Run blocks until ctx is cancelled, sweeping on each tick. Returns
// nil on clean shutdown. Safe to call as `go sw.Run(ctx)` from main.
//
// The first sweep fires after the initial Interval — not at t0 — so
// startup doesn't race against schema creation or unexpected state.
// Callers wanting an immediate sweep can call Once(ctx) before Run.
func (s *Sweeper) Run(ctx context.Context) error {
	ticker := time.NewTicker(s.config.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			s.Once(ctx)
		}
	}
}

// Once runs a single sweep cycle immediately. Logs counts; errors are
// logged but not returned (the caller — a ticker loop — can't
// meaningfully react to transient storage errors, and the next tick
// will try again).
func (s *Sweeper) Once(ctx context.Context) {
	now := s.config.Clock()

	envCutoff := now.Add(-s.config.EnvelopeMaxAge)
	envCount, err := s.store.DeleteEnvelopesOlderThan(ctx, envCutoff)
	if err != nil && !errors.Is(err, context.Canceled) {
		s.config.Logger.Printf("sweep: envelope eviction failed: %v", err)
	}

	// Pair request expiry uses the row's own expires_at — no cutoff
	// math here; just ask the store to flip anything whose expires_at
	// has passed.
	reqCount, err := s.store.ExpirePendingRequests(ctx, now)
	if err != nil && !errors.Is(err, context.Canceled) {
		s.config.Logger.Printf("sweep: pair request expiry failed: %v", err)
	}

	if envCount > 0 || reqCount > 0 {
		s.config.Logger.Printf("sweep: evicted %d envelope(s), expired %d pending request(s)", envCount, reqCount)
	}
}
