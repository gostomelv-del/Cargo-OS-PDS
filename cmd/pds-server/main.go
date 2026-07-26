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
	"cargoos/evidence"
	"cargoos/pds"
	postgresstore "cargoos/persistence/postgres"
	"cargoos/policy"
	"cargoos/ruleoperator"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	runtimeVersion := os.Getenv("PDS_RUNTIME_VERSION")
	if runtimeVersion == "" {
		runtimeVersion = "cargoos-pds.dev"
	}
	service, evidenceService, policyResolver, ruleExecutor, readiness, closeStore, err := newService(
		ctx, os.Getenv("PDS_DATABASE_URL"), runtimeVersion,
	)
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
		Handler:           httpapi.NewHandlerWithRuntime(service, evidenceService, policyResolver, ruleExecutor, readiness),
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
	runtimeVersion string,
) (*pds.Service, *evidence.Service, pds.PolicyResolver, *pds.RuleExecutionService, httpapi.ReadinessChecker, func(), error) {
	if databaseURL == "" {
		log.Print("PDS_DATABASE_URL is not set; using non-durable in-memory storage")
		evaluationService := pds.NewService(nil)
		policyRegistry := policy.NewRegistry()
		evidenceService, err := evidence.NewService(evidence.NewMemoryRepository(), evidence.ServiceConfig{
			SchemaVersion: "evidence.v1", RuntimeVersion: runtimeVersion,
		})
		if err != nil {
			return nil, nil, nil, nil, nil, func() {}, err
		}
		ruleExecutor, err := newRuleExecutionService(evaluationService, evidenceService, policyRegistry)
		return evaluationService, evidenceService, policyRegistry, ruleExecutor,
			httpapi.ReadinessFunc(func(context.Context) error { return nil }), func() {}, err
	}

	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, nil, nil, nil, nil, func() {}, err
	}
	closeDatabase := func() { _ = db.Close() }

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err = db.PingContext(pingCtx); err != nil {
		closeDatabase()
		return nil, nil, nil, nil, nil, func() {}, err
	}
	store, err := postgresstore.NewStore(db)
	if err != nil {
		closeDatabase()
		return nil, nil, nil, nil, nil, func() {}, err
	}
	evidenceService, err := evidence.NewService(store, evidence.ServiceConfig{
		SchemaVersion: "evidence.v1", RuntimeVersion: runtimeVersion,
	})
	if err != nil {
		closeDatabase()
		return nil, nil, nil, nil, nil, func() {}, err
	}
	evaluationService := pds.NewServiceWithStore(store, nil)
	ruleExecutor, err := newRuleExecutionService(evaluationService, evidenceService, store)
	if err != nil {
		closeDatabase()
		return nil, nil, nil, nil, nil, func() {}, err
	}
	log.Print("using durable PostgreSQL storage")
	return evaluationService, evidenceService, store, ruleExecutor, postgresReadiness(db), closeDatabase, nil
}

func newRuleExecutionService(
	evaluations *pds.Service,
	evidenceReader pds.EvidenceReader,
	versionReader policy.VersionReader,
) (*pds.RuleExecutionService, error) {
	resolver, err := pds.NewPolicyDocumentRuleResolver(
		versionReader,
		ruleoperator.PolicyDocumentCompiler{},
	)
	if err != nil {
		return nil, err
	}
	return pds.NewRuleExecutionServiceWithResolver(evaluations, evidenceReader, resolver)
}

func postgresReadiness(db *sql.DB) httpapi.ReadinessChecker {
	return httpapi.ReadinessFunc(func(ctx context.Context) error {
		if db == nil {
			return errors.New("database is required")
		}
		checkCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		var evaluations, history, outbox, evidenceObjects, policyVersions, policyLifecycle, trustKeys, trustRevocations bool
		err := db.QueryRowContext(checkCtx, `
			SELECT to_regclass('public.evaluations') IS NOT NULL,
			       to_regclass('public.evaluation_history') IS NOT NULL,
			       to_regclass('public.evaluation_outbox') IS NOT NULL,
			       to_regclass('public.evidence_objects') IS NOT NULL,
			       to_regclass('public.policy_versions') IS NOT NULL,
			       to_regclass('public.policy_lifecycle_events') IS NOT NULL,
			       to_regclass('public.trusted_verification_keys') IS NOT NULL,
			       to_regclass('public.trust_key_revocations') IS NOT NULL
		`).Scan(&evaluations, &history, &outbox, &evidenceObjects, &policyVersions, &policyLifecycle, &trustKeys, &trustRevocations)
		if err != nil {
			return fmt.Errorf("readiness query: %w", err)
		}
		if !evaluations || !history || !outbox || !evidenceObjects || !policyVersions || !policyLifecycle || !trustKeys || !trustRevocations {
			return errors.New("required PDS tables are missing")
		}
		return nil
	})
}
