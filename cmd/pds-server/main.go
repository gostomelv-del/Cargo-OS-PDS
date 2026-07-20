package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"cargoos/api/httpapi"
	"cargoos/pds"
	postgresstore "cargoos/persistence/postgres"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	service, readiness, closeStore, err := newService(ctx, os.Getenv("PDS_DATABASE_URL"))
	if err != nil {
		return err
	}
	defer closeStore()

	address := os.Getenv("PDS_HTTP_ADDRESS")
	if address == "" {
		address = ":8080"
	}
	server := &http.Server{
		Addr:              address,
		Handler:           httpapi.NewHandlerWithReadiness(service, readiness),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	serveErrors := make(chan error, 1)
	go func() {
		serveErrors <- server.ListenAndServe()
	}()

	log.Printf("Cargo OS PDS listening on %s", address)
	select {
	case err = <-serveErrors:
		if err != nil && err != http.ErrServerClosed {
			return err
		}
		return nil
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err = server.Shutdown(shutdownCtx); err != nil {
		return err
	}
	err = <-serveErrors
	if err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func newService(
	ctx context.Context,
	databaseURL string,
) (*pds.Service, httpapi.ReadinessChecker, func(), error) {
	if databaseURL == "" {
		log.Print("PDS_DATABASE_URL is not set; using non-durable in-memory storage")
		return pds.NewService(nil), httpapi.ReadinessFunc(func(context.Context) error { return nil }), func() {}, nil
	}

	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, nil, func() {}, err
	}
	closeDatabase := func() { _ = db.Close() }

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err = db.PingContext(pingCtx); err != nil {
		closeDatabase()
		return nil, nil, func() {}, err
	}
	store, err := postgresstore.NewStore(db)
	if err != nil {
		closeDatabase()
		return nil, nil, func() {}, err
	}
	log.Print("using durable PostgreSQL storage")
	return pds.NewServiceWithStore(store, nil), postgresReadiness(db), closeDatabase, nil
}

func postgresReadiness(db *sql.DB) httpapi.ReadinessChecker {
	return httpapi.ReadinessFunc(func(ctx context.Context) error {
		if db == nil {
			return errors.New("database is required")
		}
		checkCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		var evaluations, history, outbox, evidenceObjects bool
		err := db.QueryRowContext(checkCtx, `
			SELECT to_regclass('public.evaluations') IS NOT NULL,
			       to_regclass('public.evaluation_history') IS NOT NULL,
			       to_regclass('public.evaluation_outbox') IS NOT NULL,
			       to_regclass('public.evidence_objects') IS NOT NULL
		`).Scan(&evaluations, &history, &outbox, &evidenceObjects)
		if err != nil {
			return fmt.Errorf("readiness query: %w", err)
		}
		if !evaluations || !history || !outbox || !evidenceObjects {
			return errors.New("required PDS tables are missing")
		}
		return nil
	})
}
