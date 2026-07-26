package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	postgresstore "cargoos/persistence/postgres"
)

var (
	errDatabaseURLRequired = errors.New("PDS_DATABASE_URL is required")
	errLifecycleUsage      = errors.New("usage: pds-policy-lifecycle <suspend|retire> <policy-id> <version> <event-at-rfc3339>")
)

type lifecycleAction string

const (
	actionSuspend lifecycleAction = "suspend"
	actionRetire  lifecycleAction = "retire"
)

type lifecycleRequest struct {
	Action   lifecycleAction
	PolicyID string
	Version  string
	EventAt  time.Time
}

type lifecycleStore interface {
	Suspend(context.Context, string, string, time.Time) error
	Retire(context.Context, string, string, time.Time) error
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	databaseURL := os.Getenv("PDS_DATABASE_URL")
	if databaseURL == "" {
		return errDatabaseURLRequired
	}
	request, err := parseLifecycleRequest(os.Args[1:])
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return err
	}
	defer db.Close()
	if err = db.PingContext(ctx); err != nil {
		return err
	}
	store, err := postgresstore.NewStore(db)
	if err != nil {
		return err
	}
	if err = executeLifecycleRequest(ctx, store, request); err != nil {
		return err
	}
	log.Printf("%s policy %s version %s at %s",
		request.Action, request.PolicyID, request.Version, request.EventAt.Format(time.RFC3339Nano))
	return nil
}

func parseLifecycleRequest(args []string) (lifecycleRequest, error) {
	if len(args) != 4 {
		return lifecycleRequest{}, errLifecycleUsage
	}
	request := lifecycleRequest{
		Action:   lifecycleAction(strings.ToLower(strings.TrimSpace(args[0]))),
		PolicyID: strings.TrimSpace(args[1]),
		Version:  strings.TrimSpace(args[2]),
	}
	switch request.Action {
	case actionSuspend, actionRetire:
	default:
		return lifecycleRequest{}, errLifecycleUsage
	}
	if request.PolicyID == "" || request.Version == "" {
		return lifecycleRequest{}, errLifecycleUsage
	}
	eventAt, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(args[3]))
	if err != nil || eventAt.IsZero() {
		return lifecycleRequest{}, fmt.Errorf("%w: invalid event time", errLifecycleUsage)
	}
	request.EventAt = eventAt.UTC()
	return request, nil
}

func executeLifecycleRequest(ctx context.Context, store lifecycleStore, request lifecycleRequest) error {
	if store == nil {
		return errors.New("policy lifecycle store is required")
	}
	switch request.Action {
	case actionSuspend:
		return store.Suspend(ctx, request.PolicyID, request.Version, request.EventAt)
	case actionRetire:
		return store.Retire(ctx, request.PolicyID, request.Version, request.EventAt)
	default:
		return errLifecycleUsage
	}
}
