// Command interchange is the Nexus Frame-to-Frame relay service.
//
// v3 protocol: see docs/specs/2026-04-24-frame-to-frame-relay-spec-v3.md
// (in the agent-network repo).
//
// Two listeners:
//
//   PUBLIC  (-addr, default :8443, Funnel-exposed in production):
//     GET  /.well-known/nexus-interchange   — discovery
//     GET  /health                           — liveness
//     PUT  /mailbox/:pathId                  — append envelope
//     GET  /mailbox/:pathId?since=<msg_id>   — pull envelopes
//     POST /mailbox/:pathId/ack              — evict acked
//     POST /pair/request                     — requester initiates pair
//     GET  /pair/requests/:id                — requester polls status
//
//   TAILNET (-tailnet-addr, Tailscale-bound in production):
//     GET  /pair/requests?status=pending     — owner lists pending
//     POST /pair/requests/:id/approve        — owner approves
//     POST /pair/requests/:id/deny           — owner denies
//
// The tailnet/public split is the primary control enforcing the
// "operator approves" invariant. The PUBLIC listener has no way to
// reach approve/deny at all. An optional shared-secret check layers
// on top of the network binding via -owner-secret.
//
// Signature verification uses internal/crypto.EdVerifier (Ed25519 only
// at v1 per anvil #7828/#7841). Retention sweep runs hourly; pair
// requests TTL-expire after 24h.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/CarriedWorldUniverse/interchange/internal/crypto"
	"github.com/CarriedWorldUniverse/interchange/internal/discovery"
	"github.com/CarriedWorldUniverse/interchange/internal/landing"
	"github.com/CarriedWorldUniverse/interchange/internal/mailbox"
	"github.com/CarriedWorldUniverse/interchange/internal/middleware"
	"github.com/CarriedWorldUniverse/interchange/internal/pairflow"
	"github.com/CarriedWorldUniverse/interchange/internal/storage"
	"github.com/CarriedWorldUniverse/interchange/internal/sweep"
	"github.com/CarriedWorldUniverse/interchange/internal/version"
)

func main() {
	var (
		addr           = flag.String("addr", ":8443", "public HTTP listen address (Funnel-exposed)")
		tailnetAddr    = flag.String("tailnet-addr", "127.0.0.1:8444", "tailnet-bound listen address for owner endpoints (approve/deny/list). In production bind to tailscale0.")
		interchangeID  = flag.String("id", "", "interchange_id — the nexus_id of the owner operator's Frame")
		dbPath         = flag.String("db", "interchange.db", "SQLite database path (use :memory: for in-memory)")
		sweepInterval  = flag.Duration("sweep-interval", time.Hour, "retention sweep cadence")
		envelopeMaxAge = flag.Duration("envelope-max-age", 7*24*time.Hour, "envelope retention age; older rows evicted on sweep")
		ownerSecret    = flag.String("owner-secret", "", "optional shared secret required on owner (tailnet) endpoints — layers on top of tailnet binding. Empty = no header check.")
		showVersion    = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("interchange %s\n", version.Version)
		return
	}

	if *interchangeID == "" {
		log.Fatal("interchange: -id is required (owner nexus_id)")
	}

	logger := log.New(os.Stderr, "interchange ", log.LstdFlags|log.Lmsgprefix)

	store, err := storage.OpenSQLite(*dbPath)
	if err != nil {
		logger.Fatalf("open storage: %v", err)
	}
	defer func() { _ = store.Close() }()
	if err := store.CreateSchema(context.Background()); err != nil {
		logger.Fatalf("create schema: %v", err)
	}

	mb := &mailbox.Handler{
		Store:    store,
		Verifier: crypto.EdVerifier{},
	}
	pf := &pairflow.Handler{
		Store:       store,
		OwnerSecret: *ownerSecret,
	}

	// Public mux — everything Funnel-reachable.
	publicMux := http.NewServeMux()
	publicMux.HandleFunc("/", landing.Handler())
	publicMux.HandleFunc(discovery.Path, discovery.Handler(*interchangeID))
	publicMux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		_, _ = w.Write([]byte("ok"))
	})
	publicMux.Handle("/mailbox/", mb.Routes())
	publicMux.Handle("/pair/", pf.PublicRoutes())

	// Tailnet mux — owner-only endpoints. Served on a separate listener
	// so the network binding (not header auth) is the primary control.
	tailnetMux := http.NewServeMux()
	tailnetMux.Handle("/pair/", pf.OwnerRoutes())
	tailnetMux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	// Signal-cancelled context propagates to sweep + shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Retention sweep.
	sw := sweep.New(store, sweep.Config{
		Interval:       *sweepInterval,
		EnvelopeMaxAge: *envelopeMaxAge,
		Logger:         logger,
	})
	var sweepWG sync.WaitGroup
	sweepWG.Add(1)
	go func() {
		defer sweepWG.Done()
		if err := sw.Run(ctx); err != nil {
			logger.Printf("sweep: %v", err)
		}
	}()

	logger.Printf("public listener on %s", *addr)
	logger.Printf("tailnet listener on %s (owner endpoints — bind to tailscale0 in production)", *tailnetAddr)
	logger.Printf("interchange_id=%s db=%s sweep=%s envelope-max-age=%s", *interchangeID, *dbPath, *sweepInterval, *envelopeMaxAge)
	logger.Printf("signature verification: Ed25519 via internal/crypto")
	if *ownerSecret != "" {
		logger.Printf("owner endpoints: X-Owner-Secret header required (layered on tailnet binding)")
	} else {
		logger.Printf("owner endpoints: tailnet binding only — no shared secret configured")
	}

	// Public mux: rate-limit per (route, client-IP), then panic-recover.
	// Tighter limits on /pair/request (anonymous registration); more
	// permissive on /mailbox PUT (paired callers, but still capped).
	rateCfg := middleware.RateLimitConfig{
		Default: middleware.RateRule{PerSecond: 5, Burst: 10},
		Routes: []middleware.RouteRule{
			{Method: http.MethodPost, Prefix: "/pair/request",
				Rule: middleware.RateRule{PerSecond: 5.0 / 60, Burst: 5}}, // 5/min/IP
			{Method: http.MethodPut, Prefix: "/mailbox/",
				Rule: middleware.RateRule{PerSecond: 1, Burst: 60}}, // 60/min/IP sustained
			{Method: http.MethodGet, Prefix: "/mailbox/",
				Rule: middleware.RateRule{PerSecond: 2, Burst: 120}}, // poll-friendly
		},
		// Public listener is fronted by Tailscale Funnel which sets
		// X-Forwarded-For to the real client IP. Trust XFF here so
		// per-IP buckets isolate real callers (not the single Funnel
		// hop). If this ever changes — e.g. running the public port
		// directly without Funnel — flip this to false to prevent XFF
		// spoofing from defeating per-IP isolation.
		TrustXFF: true,
		Logger:   logger,
	}
	publicHandler, rateShutdown := middleware.RateLimit(rateCfg, publicMux)
	publicHandler = middleware.Recover(logger, publicHandler)

	// Tailnet mux: panic-recover only. Operator-trusted; no rate limit.
	tailnetHandler := middleware.Recover(logger, tailnetMux)

	publicSrv := &http.Server{Addr: *addr, Handler: publicHandler}
	tailnetSrv := &http.Server{Addr: *tailnetAddr, Handler: tailnetHandler}

	go func() {
		if err := publicSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("public serve: %v", err)
		}
	}()
	go func() {
		if err := tailnetSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("tailnet serve: %v", err)
		}
	}()

	<-ctx.Done()
	logger.Printf("shutdown requested, draining HTTP...")
	// Each server gets its own 10s drain window — sharing a single
	// timeout would let a slow public drain consume the entire budget
	// and abandon tailnet requests without a chance to complete.
	pubCtx, pubCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer pubCancel()
	_ = publicSrv.Shutdown(pubCtx)

	tailCtx, tailCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer tailCancel()
	_ = tailnetSrv.Shutdown(tailCtx)

	rateShutdown()
	sweepWG.Wait()
	logger.Printf("shutdown complete")
}
